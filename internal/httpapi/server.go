package httpapi

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"server-file-manager/internal/auth"
	"server-file-manager/internal/filemanager"
	"server-file-manager/internal/model"
	"server-file-manager/internal/store"
	"server-file-manager/web"
)

const maxJSONBody = 1 << 20

type API struct {
	DB        *store.Store
	Files     *filemanager.Manager
	DataDir   string
	TLS       bool // browser-facing URL uses HTTPS, including TLS terminated by a reverse proxy
	MaxUpload int64
	Limiter   *loginLimiter
}

func New(db *store.Store, files *filemanager.Manager, dataDir string, tls bool, maxUpload int64) *API {
	return &API{DB: db, Files: files, DataDir: dataDir, TLS: tls, MaxUpload: maxUpload, Limiter: newLoginLimiter()}
}

type contextKey string

const userContextKey contextKey = "user"

type currentUser struct {
	User model.User
	CSRF string
}

func (a *API) Handler() http.Handler {
	protected := http.NewServeMux()
	protected.HandleFunc("POST /api/auth/logout", a.logout)
	protected.HandleFunc("GET /api/me", a.me)
	protected.HandleFunc("GET /api/roots", a.roots)
	protected.HandleFunc("GET /api/files", a.listFiles)
	protected.HandleFunc("POST /api/files/upload", a.upload)
	protected.HandleFunc("GET /api/files/download", a.download)
	protected.HandleFunc("POST /api/files/actions", a.fileAction)
	protected.HandleFunc("GET /api/search", a.search)
	protected.HandleFunc("GET /api/trash", a.trashList)
	protected.HandleFunc("POST /api/trash/{id}/restore", a.restoreTrash)
	protected.HandleFunc("GET /api/admin/users", a.adminUsers)
	protected.HandleFunc("POST /api/admin/users", a.adminCreateUser)
	protected.HandleFunc("PATCH /api/admin/users/{id}/active", a.adminSetActive)
	protected.HandleFunc("PUT /api/admin/users/{id}/password", a.adminResetPassword)
	protected.HandleFunc("GET /api/admin/users/{id}/permissions", a.adminGetPermissions)
	protected.HandleFunc("PUT /api/admin/users/{id}/permissions", a.adminSetPermissions)
	protected.HandleFunc("GET /api/admin/roots", a.adminRoots)
	protected.HandleFunc("POST /api/admin/roots", a.adminCreateRoot)
	protected.HandleFunc("DELETE /api/admin/roots/{id}", a.adminDisableRoot)
	protected.HandleFunc("PATCH /api/admin/roots/{id}/active", a.adminSetRootActive)
	protected.HandleFunc("POST /api/admin/roots/preview", a.adminPreviewRoot)
	protected.HandleFunc("DELETE /api/admin/trash/{id}", a.adminPurgeTrash)

	root := http.NewServeMux()
	root.HandleFunc("POST /api/auth/login", a.login)
	root.Handle("/api/", a.authenticate(protected))
	assets := http.FileServer(http.FS(web.Files()))
	root.Handle("/", assets)
	return securityHeaders(root)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (a *API) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(auth.SessionCookie)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "请先登录")
			return
		}
		u, csrf, err := auth.Authenticate(a.DB, cookie.Value)
		if err != nil {
			clearCookie(w, a.TLS)
			writeError(w, http.StatusUnauthorized, "登录已失效")
			return
		}
		if isMutation(r.Method) {
			if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r, a.TLS) {
				writeError(w, http.StatusForbidden, "请求来源校验失败")
				return
			}
			given := r.Header.Get("X-CSRF-Token")
			if given == "" || subtle.ConstantTimeCompare([]byte(given), []byte(csrf)) != 1 {
				writeError(w, http.StatusForbidden, "请求令牌无效")
				return
			}
		}
		ctx := context.WithValue(r.Context(), userContextKey, currentUser{User: u, CSRF: csrf})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func sameOrigin(origin string, r *http.Request, publicHTTPS bool) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Host == "" {
		return false
	}
	expectedScheme := "http"
	if publicHTTPS || r.TLS != nil {
		expectedScheme = "https"
	}
	return strings.EqualFold(u.Host, r.Host) && strings.EqualFold(u.Scheme, expectedScheme)
}

func isMutation(method string) bool {
	return method != "GET" && method != "HEAD" && method != "OPTIONS"
}
func userFrom(r *http.Request) currentUser {
	v, _ := r.Context().Value(userContextKey).(currentUser)
	return v
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r, a.TLS) {
		writeError(w, http.StatusForbidden, "请求来源校验失败")
		return
	}
	if a.Limiter == nil {
		a.Limiter = newLoginLimiter()
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	if retry := a.Limiter.RetryAfter(ip); retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
		writeError(w, http.StatusTooManyRequests, "尝试次数过多，请稍后再试")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式无效")
		return
	}
	u, hash, err := a.DB.UserByUsername(strings.TrimSpace(in.Username))
	if err != nil || !u.Active || !auth.VerifyPassword(hash, in.Password) {
		a.Limiter.Fail(ip)
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	a.Limiter.Success(ip)
	session, err := auth.CreateSession(a.DB, u.ID)
	if err != nil {
		internalError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: auth.SessionCookie, Value: session.Token, Path: "/", HttpOnly: true, Secure: a.TLS, SameSite: http.SameSiteStrictMode, Expires: session.ExpiresAt, MaxAge: int(auth.SessionTTL.Seconds())})
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "csrfToken": session.CSRFToken})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.SessionCookie); err == nil {
		_ = a.DB.DeleteSession(auth.TokenHash(c.Value))
	}
	clearCookie(w, a.TLS)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
func clearCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: auth.SessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	writeJSON(w, http.StatusOK, map[string]any{"user": u.User, "csrfToken": u.CSRF})
}

func (a *API) roots(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u.User.Role == model.RoleAdmin {
		roots, err := a.DB.Roots(true)
		if err != nil {
			internalError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"roots": roots})
		return
	}
	grants, err := a.DB.UserGrants(u.User.ID)
	if err != nil {
		internalError(w, err)
		return
	}
	for i := range grants {
		grants[i].Root.Path = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": grants})
}

func (a *API) adminUsers(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	users, err := a.DB.Users()
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (a *API) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "请求格式无效")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if err := auth.ValidateUsername(in.Username); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	u, err := a.DB.CreateUser(in.Username, hash, model.RoleUser)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, 409, "用户名已存在")
		} else {
			internalError(w, err)
		}
		return
	}
	a.audit(r, "user.create", nil, u.Username, "ok")
	writeJSON(w, http.StatusCreated, map[string]any{"user": u})
}

func (a *API) adminSetActive(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	actor := userFrom(r).User
	target, err := a.DB.UserByID(id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if target.Role == model.RoleAdmin || target.ID == actor.ID {
		writeError(w, 400, "网页只能管理普通用户")
		return
	}
	var in struct {
		Active bool `json:"active"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "请求格式无效")
		return
	}
	if err := a.DB.SetUserActive(id, in.Active); err != nil {
		writeStoreError(w, err)
		return
	}
	a.audit(r, "user.active", nil, target.Username, strconv.FormatBool(in.Active))
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) adminResetPassword(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	target, err := a.DB.UserByID(id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if target.Role != model.RoleUser {
		writeError(w, 400, "网页只能重置普通用户密码")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "请求格式无效")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if err := a.DB.SetPassword(id, hash); err != nil {
		writeStoreError(w, err)
		return
	}
	a.audit(r, "user.password_reset", nil, target.Username, "ok")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) adminRoots(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	roots, err := a.DB.Roots(false)
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"roots": roots})
}

func (a *API) adminCreateRoot(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var in struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "请求格式无效")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Path = strings.TrimSpace(in.Path)
	if in.Name == "" || len(in.Name) > 100 || strings.ContainsAny(in.Name, "\r\n\x00") || in.Path == "" || len(in.Path) > 4096 {
		writeError(w, 400, "名称或目录路径无效")
		return
	}
	canonical, status, message := a.canonicalRootPath(in.Path)
	if status != http.StatusOK {
		writeError(w, status, message)
		return
	}
	u := userFrom(r).User
	created, err := a.DB.CreateRoot(in.Name, canonical, u.ID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, 409, "该目录已登记")
		} else {
			internalError(w, err)
		}
		return
	}
	a.audit(r, "root.create", &created.ID, canonical, "ok")
	writeJSON(w, 201, map[string]any{"root": created})
}

func (a *API) adminPreviewRoot(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var in struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "请求格式无效")
		return
	}
	in.Path = strings.TrimSpace(in.Path)
	if in.Path == "" || len(in.Path) > 4096 {
		writeError(w, 400, "目录路径无效")
		return
	}
	canonical, status, message := a.canonicalRootPath(in.Path)
	if status != http.StatusOK {
		writeError(w, status, message)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"path": canonical})
}

func (a *API) canonicalRootPath(raw string) (string, int, string) {
	if !filepath.IsAbs(raw) {
		return "", http.StatusBadRequest, "请输入服务器上的绝对目录路径"
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", http.StatusBadRequest, "目录路径无效"
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", http.StatusBadRequest, "目录不存在或无法访问"
	}
	info, err := os.Stat(canonical)
	if err != nil || !info.IsDir() {
		return "", http.StatusBadRequest, "请选择已存在的目录"
	}
	rootHandle, err := os.OpenRoot(canonical)
	if err != nil {
		return "", http.StatusForbidden, "当前运行账号无法访问该目录"
	}
	_ = rootHandle.Close()
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return "", http.StatusBadRequest, "目录路径无效"
	}
	dataPath, err := filepath.EvalSymlinks(a.DataDir)
	if err != nil {
		return "", http.StatusInternalServerError, "无法检查应用数据目录"
	}
	if pathsOverlap(canonical, dataPath) {
		return "", http.StatusBadRequest, "共享目录不能包含或位于应用数据目录中"
	}
	existing, err := a.DB.Roots(false)
	if err != nil {
		return "", http.StatusInternalServerError, "无法检查已有共享目录"
	}
	for _, item := range existing {
		if pathsOverlap(canonical, item.Path) {
			return "", http.StatusConflict, "该目录与已有共享目录重叠"
		}
	}
	return canonical, http.StatusOK, ""
}

func pathsOverlap(a, b string) bool {
	rel, err := filepath.Rel(a, b)
	if err != nil {
		return true
	}
	if rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return true
	}
	rel, err = filepath.Rel(b, a)
	if err != nil {
		return true
	}
	return rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func (a *API) adminDisableRoot(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.DB.SetRootActive(id, false); err != nil {
		writeStoreError(w, err)
		return
	}
	a.audit(r, "root.disable", &id, "", "ok")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) adminSetRootActive(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Active bool `json:"active"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "请求格式无效")
		return
	}
	if err := a.DB.SetRootActive(id, in.Active); err != nil {
		writeStoreError(w, err)
		return
	}
	a.audit(r, "root.active", &id, "", strconv.FormatBool(in.Active))
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) adminGetPermissions(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	uid, ok := pathID(w, r)
	if !ok {
		return
	}
	u, err := a.DB.UserByID(uid)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if u.Role != model.RoleUser {
		writeError(w, 400, "只能为普通用户配置目录权限")
		return
	}
	roots, err := a.DB.Roots(true)
	if err != nil {
		internalError(w, err)
		return
	}
	out := make([]model.RootGrant, 0, len(roots))
	for _, root := range roots {
		p, _ := a.DB.Permission(uid, root.ID)
		out = append(out, model.RootGrant{Root: root, Permissions: p})
	}
	writeJSON(w, 200, map[string]any{"grants": out})
}

func (a *API) adminSetPermissions(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	uid, ok := pathID(w, r)
	if !ok {
		return
	}
	target, err := a.DB.UserByID(uid)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if target.Role != model.RoleUser {
		writeError(w, 400, "只能为普通用户配置目录权限")
		return
	}
	var in struct {
		Grants []struct {
			RootID      int64             `json:"rootId"`
			Permissions model.Permissions `json:"permissions"`
		} `json:"grants"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "请求格式无效")
		return
	}
	roots, err := a.DB.Roots(false)
	if err != nil {
		internalError(w, err)
		return
	}
	provided := map[int64]model.Permissions{}
	for _, g := range in.Grants {
		if _, duplicate := provided[g.RootID]; duplicate {
			writeError(w, 400, "授权目录重复")
			return
		}
		provided[g.RootID] = g.Permissions
	}
	known := map[int64]bool{}
	for _, root := range roots {
		known[root.ID] = true
	}
	for rootID := range provided {
		if !known[rootID] {
			writeError(w, 400, "授权中包含未知目录")
			return
		}
	}
	if err := a.DB.ReplacePermissions(uid, roots, provided); err != nil {
		internalError(w, err)
		return
	}
	a.audit(r, "permissions.update", nil, target.Username, "ok")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) listFiles(w http.ResponseWriter, r *http.Request) {
	root, perms, ok := a.authorizedRoot(w, r, queryInt64(r, "rootId"), func(p model.Permissions) bool { return p.List })
	if !ok {
		return
	}
	path := r.URL.Query().Get("path")
	entries, err := a.Files.List(root, path)
	if err != nil {
		writeFileError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"root": root.Name, "path": path, "entries": entries, "permissions": perms})
}

func (a *API) upload(w http.ResponseWriter, r *http.Request) {
	root, _, ok := a.authorizedRoot(w, r, queryInt64(r, "rootId"), func(p model.Permissions) bool { return p.Upload })
	if !ok {
		return
	}
	if a.MaxUpload > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, a.MaxUpload)
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, 400, "上传表单无效或超过限制")
		return
	}
	defer r.MultipartForm.RemoveAll()
	path := r.FormValue("path")
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "缺少上传文件")
		return
	}
	defer file.Close()
	name := filepath.Base(strings.ReplaceAll(header.Filename, "\\", "/"))
	n, err := a.Files.Upload(root, path, name, file)
	if err != nil {
		writeFileError(w, err)
		return
	}
	a.audit(r, "file.upload", &root.ID, joinWebPath(path, name), "ok")
	writeJSON(w, 201, map[string]int64{"bytes": n})
}

func (a *API) download(w http.ResponseWriter, r *http.Request) {
	root, _, ok := a.authorizedRoot(w, r, queryInt64(r, "rootId"), func(p model.Permissions) bool { return p.Download })
	if !ok {
		return
	}
	path := r.URL.Query().Get("path")
	f, err := a.Files.Open(root, path)
	if err != nil {
		writeFileError(w, err)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeFileError(w, err)
		return
	}
	if !info.Mode().IsRegular() {
		writeError(w, 400, "只能下载普通文件")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(path)}))
	http.ServeContent(w, r, filepath.Base(path), info.ModTime(), f)
}

type fileAction struct {
	Action            string `json:"action"`
	RootID            int64  `json:"rootId"`
	Path              string `json:"path"`
	Name              string `json:"name"`
	DestinationRootID int64  `json:"destinationRootId"`
	DestinationPath   string `json:"destinationPath"`
	TrashID           string `json:"trashId"`
}

func (a *API) fileAction(w http.ResponseWriter, r *http.Request) {
	var in fileAction
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "请求格式无效")
		return
	}
	u := userFrom(r).User
	switch in.Action {
	case "create_dir":
		root, _, ok := a.authorizedRoot(w, r, in.RootID, func(p model.Permissions) bool { return p.CreateDir })
		if !ok {
			return
		}
		err := a.Files.CreateDir(root, in.Path, in.Name)
		if err != nil {
			writeFileError(w, err)
			return
		}
		a.audit(r, "file.mkdir", &root.ID, joinWebPath(in.Path, in.Name), "ok")
	case "rename":
		root, _, ok := a.authorizedRoot(w, r, in.RootID, func(p model.Permissions) bool { return p.Rename })
		if !ok {
			return
		}
		err := a.Files.Rename(root, in.Path, in.Name)
		if err != nil {
			writeFileError(w, err)
			return
		}
		a.audit(r, "file.rename", &root.ID, in.Path, "ok")
	case "delete":
		root, _, ok := a.authorizedRoot(w, r, in.RootID, func(p model.Permissions) bool { return p.Delete })
		if !ok {
			return
		}
		clean, err := filemanager.CleanRelative(in.Path, false)
		if err != nil {
			writeFileError(w, err)
			return
		}
		id, err := auth.NewOpaqueToken()
		if err != nil {
			internalError(w, err)
			return
		}
		id = strings.ReplaceAll(strings.TrimRight(id, "="), "-", "")
		stored, err := a.Files.StageTrash(root, clean, id)
		if err != nil {
			writeFileError(w, err)
			return
		}
		entry := model.TrashEntry{ID: id, RootID: root.ID, OriginalPath: filepath.ToSlash(clean), Name: filepath.Base(clean), DeletedBy: u.ID, DeletedAt: time.Now().UTC()}
		if err := a.DB.CreateTrash(entry, stored); err != nil {
			_ = a.Files.Purge(stored)
			internalError(w, err)
			return
		}
		if err := a.Files.Remove(root, clean); err != nil {
			// Source removal may have been partial. Keep the staged copy visible
			// in the recoverable trash instead of risking loss during cleanup.
			_ = a.DB.SetTrashReady(id)
			a.audit(r, "file.delete", &root.ID, filepath.ToSlash(clean), "source_remove_failed_backup_kept")
			writeFileError(w, err)
			return
		}
		if err := a.DB.SetTrashReady(id); err != nil {
			internalError(w, err)
			return
		}
		a.audit(r, "file.delete", &root.ID, filepath.ToSlash(clean), "ok")
	case "copy", "move":
		needSource := func(p model.Permissions) bool {
			if in.Action == "copy" {
				return p.Copy
			}
			return p.Move
		}
		src, _, ok := a.authorizedRoot(w, r, in.RootID, needSource)
		if !ok {
			return
		}
		dst, _, ok := a.authorizedRoot(w, r, in.DestinationRootID, func(p model.Permissions) bool { return p.Upload })
		if !ok {
			return
		}
		var err error
		if in.Action == "copy" {
			err = a.Files.Copy(src, in.Path, dst, in.DestinationPath)
		} else {
			err = a.Files.Move(src, in.Path, dst, in.DestinationPath)
		}
		if err != nil {
			writeFileError(w, err)
			return
		}
		a.audit(r, "file."+in.Action, &src.ID, in.Path, "ok")
	default:
		writeError(w, 400, "不支持的文件操作")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) trashList(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r).User
	entries, err := a.DB.TrashEntries(u.ID, u.Role == model.RoleAdmin)
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"entries": entries})
}

func (a *API) restoreTrash(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r).User
	id := r.PathValue("id")
	entry, stored, err := a.DB.Trash(id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if u.Role != model.RoleAdmin && entry.DeletedBy != u.ID {
		writeError(w, 404, "回收站项目不存在")
		return
	}
	root, _, ok := a.authorizedRoot(w, r, entry.RootID, func(p model.Permissions) bool { return p.Upload })
	if !ok {
		return
	}
	if err := a.DB.SetTrashRestoring(id); err != nil {
		writeStoreError(w, err)
		return
	}
	if err := a.Files.Restore(stored, root, entry.OriginalPath); err != nil {
		_ = a.DB.ResetTrashReady(id)
		writeFileError(w, err)
		return
	}
	if err := a.DB.MarkRestored(id); err != nil {
		internalError(w, err)
		return
	}
	a.audit(r, "trash.restore", &root.ID, entry.OriginalPath, "ok")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) adminPurgeTrash(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	entry, stored, err := a.DB.Trash(id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err := a.DB.SetTrashPurging(id); err != nil {
		writeStoreError(w, err)
		return
	}
	if err := a.Files.Purge(stored); err != nil {
		_ = a.DB.ResetTrashReady(id)
		writeFileError(w, err)
		return
	}
	if err := a.DB.MarkPurged(id); err != nil {
		internalError(w, err)
		return
	}
	rootID := entry.RootID
	a.audit(r, "trash.purge", &rootID, entry.OriginalPath, "ok")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *API) search(w http.ResponseWriter, r *http.Request) {
	root, _, ok := a.authorizedRoot(w, r, queryInt64(r, "rootId"), func(p model.Permissions) bool { return p.Search && p.List })
	if !ok {
		return
	}
	query := r.URL.Query().Get("q")
	entries, err := a.Files.Search(root, r.URL.Query().Get("path"), query, 500)
	if err != nil {
		writeFileError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"entries": entries})
}

func (a *API) authorizedRoot(w http.ResponseWriter, r *http.Request, id int64, allow func(model.Permissions) bool) (model.Root, model.Permissions, bool) {
	u := userFrom(r).User
	root, err := a.DB.Root(id)
	if err != nil || !root.Active {
		writeError(w, 404, "目录不存在或不可访问")
		return root, model.Permissions{}, false
	}
	if u.Role == model.RoleAdmin {
		return root, allPermissions(), true
	}
	p, err := a.DB.Permission(u.ID, id)
	if err != nil || !allow(p) {
		writeError(w, 404, "目录不存在或不可访问")
		return root, p, false
	}
	return root, p, true
}
func allPermissions() model.Permissions {
	return model.Permissions{List: true, Download: true, Upload: true, CreateDir: true, Rename: true, Delete: true, Copy: true, Move: true, Search: true}
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if userFrom(r).User.Role != model.RoleAdmin {
		writeError(w, 403, "需要管理员权限")
		return false
	}
	return true
}
func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, 400, "ID 无效")
		return 0, false
	}
	return id, true
}
func queryInt64(r *http.Request, key string) int64 {
	id, _ := strconv.ParseInt(r.URL.Query().Get(key), 10, 64)
	return id
}

func (a *API) audit(r *http.Request, action string, rootID *int64, path, result string) {
	id := userFrom(r).User.ID
	a.DB.Audit(&id, action, rootID, path, result)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func internalError(w http.ResponseWriter, err error) {
	slog.Error("request failed", "error", err)
	writeError(w, http.StatusInternalServerError, "服务器内部错误")
}
func writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "记录不存在")
		return
	}
	internalError(w, err)
}
func writeFileError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, filemanager.ErrInvalidPath):
		writeError(w, 400, "路径或文件名无效")
	case errors.Is(err, filemanager.ErrSymlink):
		writeError(w, 403, "不允许通过符号链接访问文件")
	case errors.Is(err, filemanager.ErrExists):
		writeError(w, 409, "目标名称已存在")
	case errors.Is(err, os.ErrNotExist):
		writeError(w, 404, "文件或目录不存在")
	case errors.Is(err, os.ErrPermission):
		writeError(w, 403, "运行账号无权访问该文件")
	default:
		internalError(w, err)
	}
}
func joinWebPath(dir, name string) string {
	if dir == "" || dir == "." {
		return name
	}
	return pathJoin(dir, name)
}
func pathJoin(a, b string) string { return strings.TrimSuffix(a, "/") + "/" + b }

type loginAttempt struct {
	Count int
	Until time.Time
	Last  time.Time
}
type loginLimiter struct {
	mu    sync.Mutex
	items map[string]loginAttempt
}

func newLoginLimiter() *loginLimiter { return &loginLimiter{items: map[string]loginAttempt{}} }
func (l *loginLimiter) RetryAfter(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := l.items[ip]
	if time.Now().Before(v.Until) {
		return time.Until(v.Until)
	}
	return 0
}
func (l *loginLimiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	v := l.items[ip]
	if now.Sub(v.Last) > 10*time.Minute {
		v.Count = 0
	}
	v.Count++
	v.Last = now
	if v.Count >= 5 {
		v.Until = now.Add(5 * time.Minute)
		v.Count = 0
	}
	l.items[ip] = v
}
func (l *loginLimiter) Success(ip string) { l.mu.Lock(); delete(l.items, ip); l.mu.Unlock() }

func Run(addr, cert, key string, handler http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
	if cert != "" && key != "" {
		return srv.ListenAndServeTLS(cert, key)
	}
	return srv.ListenAndServe()
}
