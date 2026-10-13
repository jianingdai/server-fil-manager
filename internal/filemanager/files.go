package filemanager

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"server-file-manager/internal/model"
)

var (
	ErrInvalidPath = errors.New("invalid relative path")
	ErrSymlink     = errors.New("symbolic links are not allowed")
	ErrExists      = errors.New("destination already exists")
)

type Manager struct {
	dataRoot *os.Root
	moveMu   sync.Mutex
}

func New(dataDir string) (*Manager, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dataDir, 0700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return nil, err
	}
	if err := root.MkdirAll("trash", 0700); err != nil {
		root.Close()
		return nil, err
	}
	return &Manager{dataRoot: root}, nil
}

func (m *Manager) Close() error { return m.dataRoot.Close() }

// BrowseDirectories lists only real directories and never follows symbolic
// links. The requested path is an absolute server path and is only exposed by
// the administrator-only API.
func (m *Manager) BrowseDirectories(requested string) (model.DirectoryBrowser, error) {
	if !filepath.IsAbs(requested) || strings.ContainsRune(requested, 0) {
		return model.DirectoryBrowser{}, ErrInvalidPath
	}
	for _, part := range strings.Split(filepath.ToSlash(requested), "/") {
		if part == ".." {
			return model.DirectoryBrowser{}, ErrInvalidPath
		}
	}
	clean := filepath.Clean(requested)
	if clean != requested {
		return model.DirectoryBrowser{}, ErrInvalidPath
	}
	if err := rejectSymlinkPath(clean); err != nil {
		return model.DirectoryBrowser{}, err
	}
	info, err := os.Stat(clean)
	if err != nil {
		return model.DirectoryBrowser{}, err
	}
	if !info.IsDir() {
		return model.DirectoryBrowser{}, ErrInvalidPath
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		return model.DirectoryBrowser{}, err
	}
	result := model.DirectoryBrowser{Path: clean, Directories: make([]model.Directory, 0)}
	if clean != string(os.PathSeparator) {
		result.Parent = filepath.Dir(clean)
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		entryInfo, err := entry.Info()
		if err != nil || !entryInfo.IsDir() || entryInfo.Mode()&os.ModeSymlink != 0 {
			continue
		}
		result.Directories = append(result.Directories, model.Directory{Name: entry.Name(), Path: filepath.Join(clean, entry.Name())})
	}
	return result, nil
}

func rejectSymlinkPath(abs string) error {
	current := string(os.PathSeparator)
	for _, part := range strings.Split(strings.TrimPrefix(abs, current), current) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrSymlink
		}
	}
	return nil
}

func CleanRelative(input string, allowRoot bool) (string, error) {
	if strings.ContainsRune(input, 0) || path.IsAbs(input) {
		return "", ErrInvalidPath
	}
	if input == "" || input == "." {
		if allowRoot {
			return ".", nil
		}
		return "", ErrInvalidPath
	}
	for _, part := range strings.Split(input, "/") {
		if part == ".." || part == "." || part == "" {
			return "", ErrInvalidPath
		}
	}
	clean := path.Clean(input)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", ErrInvalidPath
	}
	return filepath.FromSlash(clean), nil
}

func CleanName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return ErrInvalidPath
	}
	return nil
}

func openRoot(rootPath string) (*os.Root, error) {
	abs, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrSymlink
	}
	if !info.IsDir() {
		return nil, fs.ErrNotExist
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(canonical) != filepath.Clean(abs) {
		return nil, ErrSymlink
	}
	return os.OpenRoot(rootPath)
}

func rootReadDir(root *os.Root, relative string) ([]os.DirEntry, error) {
	f, err := root.Open(relative)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}

func checkNoSymlinks(root *os.Root, rel string, allowMissing bool) error {
	if rel == "." {
		return nil
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	current := ""
	for i, part := range parts {
		if current == "" {
			current = part
		} else {
			current = filepath.Join(current, part)
		}
		info, err := root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && allowMissing {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrSymlink
		}
		if i < len(parts)-1 && !info.IsDir() {
			return fs.ErrNotExist
		}
	}
	return nil
}

func (m *Manager) List(root model.Root, relative string) ([]model.FileEntry, error) {
	rel, err := CleanRelative(relative, true)
	if err != nil {
		return nil, err
	}
	r, err := openRoot(root.Path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if err := checkNoSymlinks(r, rel, false); err != nil {
		return nil, err
	}
	entries, err := rootReadDir(r, rel)
	if err != nil {
		return nil, err
	}
	out := make([]model.FileEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".sfm-upload-") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		kind := "file"
		if info.IsDir() {
			kind = "directory"
		}
		if info.Mode()&os.ModeSymlink != 0 {
			kind = "symlink"
		} else if !info.IsDir() && !info.Mode().IsRegular() {
			kind = "unsupported"
		}
		child := entry.Name()
		if rel != "." {
			child = filepath.ToSlash(filepath.Join(rel, entry.Name()))
		}
		out = append(out, model.FileEntry{Name: entry.Name(), Path: child, Kind: kind, Size: info.Size(), ModTime: info.ModTime().Format(time.RFC3339), Mode: info.Mode().String()})
	}
	return out, nil
}

func (m *Manager) Open(root model.Root, relative string) (*os.File, error) {
	rel, err := CleanRelative(relative, false)
	if err != nil {
		return nil, err
	}
	r, err := openRoot(root.Path)
	if err != nil {
		return nil, err
	}
	if err := checkNoSymlinks(r, rel, false); err != nil {
		r.Close()
		return nil, err
	}
	f, err := r.Open(rel)
	if err != nil {
		r.Close()
		return nil, err
	}
	// A file descriptor remains valid after the Root is closed.
	_ = r.Close()
	return f, nil
}

func (m *Manager) Upload(root model.Root, dir, name string, src io.Reader) (int64, error) {
	if err := CleanName(name); err != nil {
		return 0, err
	}
	dirRel, err := CleanRelative(dir, true)
	if err != nil {
		return 0, err
	}
	r, err := openRoot(root.Path)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	if err := checkNoSymlinks(r, dirRel, false); err != nil {
		return 0, err
	}
	target := name
	if dirRel != "." {
		target = filepath.Join(dirRel, name)
	}
	if _, err := r.Lstat(target); err == nil {
		return 0, ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	tmp := filepath.Join(dirRel, ".sfm-upload-"+randomSuffix())
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(f, src)
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil {
		_ = r.Remove(tmp)
		return n, copyErr
	}
	if syncErr != nil {
		_ = r.Remove(tmp)
		return n, syncErr
	}
	if closeErr != nil {
		_ = r.Remove(tmp)
		return n, closeErr
	}
	// Linking publishes the completed upload atomically and refuses to replace an
	// existing name. The temporary and final entries live in the same directory.
	if err := r.Link(tmp, target); err != nil {
		_ = r.Remove(tmp)
		if errors.Is(err, os.ErrExist) {
			return n, ErrExists
		}
		return n, err
	}
	if err := r.Remove(tmp); err != nil {
		return n, err
	}
	return n, nil
}

func (m *Manager) CreateDir(root model.Root, parent, name string) error {
	if err := CleanName(name); err != nil {
		return err
	}
	parentRel, err := CleanRelative(parent, true)
	if err != nil {
		return err
	}
	r, err := openRoot(root.Path)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := checkNoSymlinks(r, parentRel, false); err != nil {
		return err
	}
	dest := name
	if parentRel != "." {
		dest = filepath.Join(parentRel, name)
	}
	if err := r.Mkdir(dest, 0700); errors.Is(err, os.ErrExist) {
		return ErrExists
	} else {
		return err
	}
}

func (m *Manager) Rename(root model.Root, relative, newName string) error {
	if err := CleanName(newName); err != nil {
		return err
	}
	src, err := CleanRelative(relative, false)
	if err != nil {
		return err
	}
	r, err := openRoot(root.Path)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := checkNoSymlinks(r, src, false); err != nil {
		return err
	}
	m.moveMu.Lock()
	defer m.moveMu.Unlock()
	info, err := r.Lstat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return errors.New("仅支持普通文件和目录")
	}
	parent := filepath.Dir(src)
	dest := newName
	if parent != "." {
		dest = filepath.Join(parent, newName)
	}
	if _, err := r.Lstat(dest); err == nil {
		return ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return r.Rename(src, dest)
}

func (m *Manager) Copy(srcRoot model.Root, srcPath string, dstRoot model.Root, dstPath string) error {
	src, err := CleanRelative(srcPath, false)
	if err != nil {
		return err
	}
	dst, err := CleanRelative(dstPath, false)
	if err != nil {
		return err
	}
	sr, err := openRoot(srcRoot.Path)
	if err != nil {
		return err
	}
	defer sr.Close()
	dr, err := openRoot(dstRoot.Path)
	if err != nil {
		return err
	}
	defer dr.Close()
	if err := checkNoSymlinks(sr, src, false); err != nil {
		return err
	}
	if srcRoot.ID == dstRoot.ID && (dst == src || strings.HasPrefix(filepath.ToSlash(dst), strings.TrimSuffix(filepath.ToSlash(src), "/")+"/")) {
		return ErrInvalidPath
	}
	if err := checkNoSymlinks(dr, filepath.Dir(dst), false); err != nil {
		return err
	}
	if _, err := dr.Lstat(dst); err == nil {
		return ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := copyNode(sr, src, dr, dst); err != nil {
		_ = dr.RemoveAll(dst)
		return err
	}
	return nil
}

func (m *Manager) Move(srcRoot model.Root, srcPath string, dstRoot model.Root, dstPath string) error {
	src, err := CleanRelative(srcPath, false)
	if err != nil {
		return err
	}
	dst, err := CleanRelative(dstPath, false)
	if err != nil {
		return err
	}
	sr, err := openRoot(srcRoot.Path)
	if err != nil {
		return err
	}
	defer sr.Close()
	if err := checkNoSymlinks(sr, src, false); err != nil {
		return err
	}
	if srcRoot.ID == dstRoot.ID {
		m.moveMu.Lock()
		defer m.moveMu.Unlock()
		if err := checkNoSymlinks(sr, filepath.Dir(dst), false); err != nil {
			return err
		}
		if _, err := sr.Lstat(dst); err == nil {
			return ErrExists
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		info, err := sr.Lstat(src)
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("仅支持普通文件和目录")
		}
		if info.IsDir() && strings.HasPrefix(filepath.ToSlash(dst)+"/", strings.TrimSuffix(filepath.ToSlash(src), "/")+"/") {
			return ErrInvalidPath
		}
		return sr.Rename(src, dst)
	}
	if err := m.Copy(srcRoot, srcPath, dstRoot, dstPath); err != nil {
		return err
	}
	if err := sr.RemoveAll(src); err != nil {
		// Keep the completed destination if source removal partially failed. A
		// duplicate is safer than deleting the only complete copy.
		return err
	}
	return nil
}

func (m *Manager) StageTrash(root model.Root, relative, trashID string) (string, error) {
	src, err := CleanRelative(relative, false)
	if err != nil {
		return "", err
	}
	sr, err := openRoot(root.Path)
	if err != nil {
		return "", err
	}
	defer sr.Close()
	if err := checkNoSymlinks(sr, src, false); err != nil {
		return "", err
	}
	dest := filepath.ToSlash(filepath.Join("trash", trashID))
	if err := copyNode(sr, src, m.dataRoot, dest); err != nil {
		_ = m.dataRoot.RemoveAll(dest)
		return "", err
	}
	return dest, nil
}

func (m *Manager) Remove(root model.Root, relative string) error {
	rel, err := CleanRelative(relative, false)
	if err != nil {
		return err
	}
	r, err := openRoot(root.Path)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := checkNoSymlinks(r, rel, false); err != nil {
		return err
	}
	return r.RemoveAll(rel)
}

func (m *Manager) Exists(root model.Root, relative string) bool {
	rel, err := CleanRelative(relative, false)
	if err != nil {
		return false
	}
	r, err := openRoot(root.Path)
	if err != nil {
		return false
	}
	defer r.Close()
	_, err = r.Lstat(rel)
	return err == nil
}

func (m *Manager) Restore(stored string, root model.Root, target string) error {
	src, err := CleanRelative(stored, false)
	if err != nil {
		return err
	}
	dst, err := CleanRelative(target, false)
	if err != nil {
		return err
	}
	dr, err := openRoot(root.Path)
	if err != nil {
		return err
	}
	defer dr.Close()
	if err := checkNoSymlinks(dr, filepath.Dir(dst), false); err != nil {
		return err
	}
	if _, err := dr.Lstat(dst); err == nil {
		return ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := copyNode(m.dataRoot, src, dr, dst); err != nil {
		_ = dr.RemoveAll(dst)
		return err
	}
	if err := m.dataRoot.RemoveAll(src); err != nil {
		// Preserve the restored copy if cleanup of the stored copy partially
		// failed; the caller can leave the trash entry available for recovery.
		return err
	}
	return nil
}

func (m *Manager) HasStored(stored string) (bool, error) {
	rel, err := CleanRelative(stored, false)
	if err != nil {
		return false, err
	}
	_, err = m.dataRoot.Lstat(rel)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (m *Manager) Purge(stored string) error {
	rel, err := CleanRelative(stored, false)
	if err != nil {
		return err
	}
	return m.dataRoot.RemoveAll(rel)
}

func (m *Manager) Search(root model.Root, base, query string, limit int) ([]model.FileEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rel, err := CleanRelative(base, true)
	if err != nil {
		return nil, err
	}
	r, err := openRoot(root.Path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if err := checkNoSymlinks(r, rel, false); err != nil {
		return nil, err
	}
	needle := strings.ToLower(strings.TrimSpace(query))
	if needle == "" {
		return nil, errors.New("搜索词不能为空")
	}
	var out []model.FileEntry
	visited := 0
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		if len(out) >= limit || depth > 32 {
			return nil
		}
		entries, e := rootReadDir(r, dir)
		if e != nil {
			return e
		}
		for _, entry := range entries {
			visited++
			if visited > 100000 {
				return nil
			}
			if len(out) >= limit {
				break
			}
			if strings.HasPrefix(entry.Name(), ".sfm-upload-") {
				continue
			}
			if entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			child := entry.Name()
			if dir != "." {
				child = filepath.ToSlash(filepath.Join(dir, entry.Name()))
			}
			info, e := entry.Info()
			if e != nil {
				continue
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				continue
			}
			kind := "file"
			if info.IsDir() {
				kind = "directory"
			}
			if strings.Contains(strings.ToLower(entry.Name()), needle) {
				out = append(out, model.FileEntry{Name: entry.Name(), Path: child, Kind: kind, Size: info.Size(), ModTime: info.ModTime().Format(time.RFC3339), Mode: info.Mode().String()})
			}
			if info.IsDir() {
				if e := walk(child, depth+1); e != nil && !errors.Is(e, os.ErrPermission) {
					return e
				}
			}
		}
		return nil
	}
	if err := walk(rel, 0); err != nil {
		return nil, err
	}
	return out, nil
}

func copyNode(srcRoot *os.Root, src string, dstRoot *os.Root, dst string) error {
	if err := checkNoSymlinks(srcRoot, src, false); err != nil {
		return err
	}
	info, err := srcRoot.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrSymlink
	}
	if info.IsDir() {
		if err := dstRoot.Mkdir(dst, info.Mode().Perm()|0700); err != nil {
			if errors.Is(err, os.ErrExist) {
				return ErrExists
			}
			return err
		}
		entries, err := rootReadDir(srcRoot, src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Type()&os.ModeSymlink != 0 {
				return ErrSymlink
			}
			childSrc := filepath.Join(src, entry.Name())
			childDst := filepath.Join(dst, entry.Name())
			if err := copyNode(srcRoot, childSrc, dstRoot, childDst); err != nil {
				return err
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return errors.New("仅支持普通文件和目录")
	}
	in, err := srcRoot.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := dstRoot.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		_ = dstRoot.Remove(dst)
		return copyErr
	}
	if syncErr != nil {
		_ = dstRoot.Remove(dst)
		return syncErr
	}
	if closeErr != nil {
		_ = dstRoot.Remove(dst)
		return closeErr
	}
	return nil
}

func randomSuffix() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}
