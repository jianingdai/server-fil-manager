package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"server-file-manager/internal/auth"
	"server-file-manager/internal/filemanager"
	"server-file-manager/internal/model"
	"server-file-manager/internal/store"
)

type testEnv struct {
	api                                        *API
	db                                         *store.Store
	files                                      *filemanager.Manager
	admin                                      model.User
	user                                       model.User
	root                                       model.Root
	adminToken, adminCSRF, userToken, userCSRF string
}

func newTestEnv(t *testing.T) testEnv {
	t.Helper()
	base := t.TempDir()
	data := filepath.Join(base, "data")
	db, err := store.Open(filepath.Join(data, "manager.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filemanager.New(data)
	if err != nil {
		t.Fatal(err)
	}
	adminHash, err := auth.HashPassword("admin-test-password")
	if err != nil {
		t.Fatal(err)
	}
	userHash, err := auth.HashPassword("user-test-password")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := db.CreateUser("admin", adminHash, model.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	user, err := db.CreateUser("worker", userHash, model.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(base, "shared")
	if err := os.Mkdir(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := db.CreateRoot("Shared", rootPath, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetPermissions(user.ID, root.ID, model.Permissions{List: true}); err != nil {
		t.Fatal(err)
	}
	as, err := auth.CreateSession(db, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	us, err := auth.CreateSession(db, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	e := testEnv{api: New(db, files, data, false, 0), db: db, files: files, admin: admin, user: user, root: root, adminToken: as.Token, adminCSRF: as.CSRFToken, userToken: us.Token, userCSRF: us.CSRFToken}
	t.Cleanup(func() { _ = files.Close(); _ = db.Close() })
	return e
}

func call(handler http.Handler, method, target, token, csrf string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	if token != "" {
		r.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if len(body) > 0 {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestPermissionChecksAndCSRF(t *testing.T) {
	e := newTestEnv(t)
	handler := e.api.Handler()
	response := call(handler, "GET", "/api/files?rootId=1", "", "", nil)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous list status=%d", response.Code)
	}
	response = call(handler, "GET", "/api/files?rootId=1", e.userToken, "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("authorized browse status=%d body=%s", response.Code, response.Body.String())
	}
	response = call(handler, "POST", "/api/files/actions", e.userToken, "wrong", []byte(`{"action":"create_dir","rootId":1,"path":".","name":"blocked"}`))
	if response.Code != http.StatusForbidden {
		t.Fatalf("bad csrf status=%d", response.Code)
	}
	response = call(handler, "POST", "/api/files/actions", e.userToken, e.userCSRF, []byte(`{"action":"create_dir","rootId":1,"path":".","name":"blocked"}`))
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing create permission status=%d body=%s", response.Code, response.Body.String())
	}
	if err := e.db.SetPermissions(e.user.ID, e.root.ID, model.Permissions{List: true, CreateDir: true}); err != nil {
		t.Fatal(err)
	}
	response = call(handler, "POST", "/api/files/actions", e.userToken, e.userCSRF, []byte(`{"action":"create_dir","rootId":1,"path":".","name":"created"}`))
	if response.Code != http.StatusOK {
		t.Fatalf("granted create status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(filepath.Join(e.root.Path, "created")); err != nil {
		t.Fatal(err)
	}
}

func TestRootWithNoGrantedPermissionsIsHidden(t *testing.T) {
	e := newTestEnv(t)
	if err := e.db.SetPermissions(e.user.ID, e.root.ID, model.Permissions{}); err != nil {
		t.Fatal(err)
	}
	response := call(e.api.Handler(), "GET", "/api/roots", e.userToken, "", nil)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), e.root.Name) {
		t.Fatalf("ungranted root leaked to user: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestLoginLogoutAndAccountRevocation(t *testing.T) {
	e := newTestEnv(t)
	handler := e.api.Handler()
	login := call(handler, "POST", "/api/auth/login", "", "", []byte(`{"username":"worker","password":"user-test-password"}`))
	if login.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.Code, login.Body.String())
	}
	var result struct {
		CSRF string `json:"csrfToken"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.CSRF == "" {
		t.Fatal("login returned no CSRF token")
	}
	cookie := login.Result().Cookies()
	if len(cookie) == 0 || cookie[0].Name != auth.SessionCookie || !cookie[0].HttpOnly {
		t.Fatalf("unexpected session cookies: %#v", cookie)
	}
	token := cookie[0].Value
	response := call(handler, "GET", "/api/me", token, "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("me status=%d", response.Code)
	}
	if err := e.db.SetUserActive(e.user.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := e.db.SetUserActive(e.user.ID, true); err != nil {
		t.Fatal(err)
	}
	response = call(handler, "GET", "/api/me", token, "", nil)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session status=%d", response.Code)
	}
}

func TestAdminCannotShareApplicationDataDirectory(t *testing.T) {
	e := newTestEnv(t)
	handler := e.api.Handler()
	body, _ := json.Marshal(map[string]string{"name": "Private data", "path": e.api.DataDir})
	response := call(handler, "POST", "/api/admin/roots", e.adminToken, e.adminCSRF, body)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("data root share status=%d body=%s", response.Code, response.Body.String())
	}
	other := filepath.Join(t.TempDir(), "new-root")
	if err := os.Mkdir(other, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "root-alias")
	if err := os.Symlink(other, alias); err != nil {
		t.Fatal(err)
	}
	previewBody, _ := json.Marshal(map[string]string{"path": alias})
	response = call(handler, "POST", "/api/admin/roots/preview", e.adminToken, e.adminCSRF, previewBody)
	if response.Code != http.StatusOK {
		t.Fatalf("root preview status=%d body=%s", response.Code, response.Body.String())
	}
	var preview struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &preview); err != nil || preview.Path != other {
		t.Fatalf("canonical preview path=%q err=%v", preview.Path, err)
	}
	body, _ = json.Marshal(map[string]string{"name": "New share", "path": other})
	response = call(handler, "POST", "/api/admin/roots", e.adminToken, e.adminCSRF, body)
	if response.Code != http.StatusCreated {
		t.Fatalf("add root status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "New share") {
		t.Fatalf("unexpected body: %s", response.Body.String())
	}
}

func TestCrossRootOperationsRequireBothGrants(t *testing.T) {
	e := newTestEnv(t)
	handler := e.api.Handler()
	source := filepath.Join(e.root.Path, "source.txt")
	if err := os.WriteFile(source, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	otherPath := filepath.Join(t.TempDir(), "other")
	if err := os.Mkdir(otherPath, 0700); err != nil {
		t.Fatal(err)
	}
	other, err := e.db.CreateRoot("Other", otherPath, e.admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.SetPermissions(e.user.ID, e.root.ID, model.Permissions{List: true, Copy: true, Move: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.db.SetPermissions(e.user.ID, other.ID, model.Permissions{List: true}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action":"copy","rootId":1,"path":"source.txt","destinationRootId":2,"destinationPath":"copy.txt"}`)
	response := call(handler, "POST", "/api/files/actions", e.userToken, e.userCSRF, body)
	if response.Code != http.StatusNotFound {
		t.Fatalf("copy without destination upload status=%d body=%s", response.Code, response.Body.String())
	}
	if err := e.db.SetPermissions(e.user.ID, other.ID, model.Permissions{List: true, Upload: true}); err != nil {
		t.Fatal(err)
	}
	response = call(handler, "POST", "/api/files/actions", e.userToken, e.userCSRF, body)
	if response.Code != http.StatusOK {
		t.Fatalf("authorized copy status=%d body=%s", response.Code, response.Body.String())
	}
	if got, err := os.ReadFile(filepath.Join(otherPath, "copy.txt")); err != nil || string(got) != "payload" {
		t.Fatalf("copy contents=%q err=%v", got, err)
	}
	move := []byte(`{"action":"move","rootId":1,"path":"source.txt","destinationRootId":2,"destinationPath":"moved.txt"}`)
	response = call(handler, "POST", "/api/files/actions", e.userToken, e.userCSRF, move)
	if response.Code != http.StatusOK {
		t.Fatalf("authorized move status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("move left source: %v", err)
	}
}

func TestDeleteAndRestoreThroughAPI(t *testing.T) {
	e := newTestEnv(t)
	handler := e.api.Handler()
	path := filepath.Join(e.root.Path, "report.txt")
	if err := os.WriteFile(path, []byte("report"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.db.SetPermissions(e.user.ID, e.root.ID, model.Permissions{List: true, Delete: true, Upload: true}); err != nil {
		t.Fatal(err)
	}
	response := call(handler, "POST", "/api/files/actions", e.userToken, e.userCSRF, []byte(`{"action":"delete","rootId":1,"path":"report.txt"}`))
	if response.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("deleted file still exists: %v", err)
	}
	response = call(handler, "GET", "/api/trash", e.userToken, "", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "report.txt") {
		t.Fatalf("trash list status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Entries []model.TrashEntry `json:"entries"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Entries) != 1 {
		t.Fatalf("trash entries=%d", len(payload.Entries))
	}
	if err := e.db.SetPermissions(e.user.ID, e.root.ID, model.Permissions{List: true}); err != nil {
		t.Fatal(err)
	}
	response = call(handler, "GET", "/api/trash", e.userToken, "", nil)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "report.txt") {
		t.Fatalf("revoked user still sees trash metadata: status=%d body=%s", response.Code, response.Body.String())
	}
	restoreURL := "/api/trash/" + payload.Entries[0].ID + "/restore"
	response = call(handler, "POST", restoreURL, e.userToken, e.userCSRF, []byte(`{}`))
	if response.Code != http.StatusNotFound {
		t.Fatalf("restore without upload permission status=%d body=%s", response.Code, response.Body.String())
	}
	if err := e.db.SetPermissions(e.user.ID, e.root.ID, model.Permissions{List: true, Upload: true}); err != nil {
		t.Fatal(err)
	}
	response = call(handler, "POST", restoreURL, e.userToken, e.userCSRF, []byte(`{}`))
	if response.Code != http.StatusOK {
		t.Fatalf("restore status=%d body=%s", response.Code, response.Body.String())
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "report" {
		t.Fatalf("restored file contents=%q err=%v", got, err)
	}
}
