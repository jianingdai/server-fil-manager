package filemanager

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"server-file-manager/internal/model"
)

func TestCleanRelativeRejectsTraversal(t *testing.T) {
	for _, input := range []string{"../secret", "a/../secret", "/etc/passwd", "a//b", "a/./b"} {
		if _, err := CleanRelative(input, false); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("CleanRelative(%q) error = %v, want ErrInvalidPath", input, err)
		}
	}
	if rel, err := CleanRelative("", true); err != nil || rel != "." {
		t.Fatalf("root path result = %q, %v", rel, err)
	}
}

func TestFileOperationsAndRecoverableTrash(t *testing.T) {
	base := t.TempDir()
	rootAPath := filepath.Join(base, "root-a")
	rootBPath := filepath.Join(base, "root-b")
	data := filepath.Join(base, "data")
	for _, dir := range []string{rootAPath, rootBPath} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	manager, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	rootA := model.Root{ID: 1, Path: rootAPath}
	rootB := model.Root{ID: 2, Path: rootBPath}

	if err := manager.CreateDir(rootA, ".", "docs"); err != nil {
		t.Fatal(err)
	}
	n, err := manager.Upload(rootA, "docs", "hello.txt", bytes.NewBufferString("hello"))
	if err != nil || n != 5 {
		t.Fatalf("upload = %d, %v", n, err)
	}
	if _, err := manager.Upload(rootA, "docs", "hello.txt", bytes.NewBufferString("replace")); !errors.Is(err, ErrExists) {
		t.Fatalf("upload overwrite error = %v, want ErrExists", err)
	}
	if err := manager.Copy(rootA, "docs/hello.txt", rootB, "copied.txt"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Move(rootB, "copied.txt", rootA, "docs/moved.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(rootBPath, "copied.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("move left source behind: %v", err)
	}
	if err := manager.Copy(rootA, "docs", rootA, "docs/archive"); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("copy into child error = %v, want ErrInvalidPath", err)
	}

	stored, err := manager.StageTrash(rootA, "docs/hello.txt", "entry-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Remove(rootA, "docs/hello.txt"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(stored, rootA, "docs/restored.txt"); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(rootAPath, "docs", "restored.txt"))
	if err != nil || string(contents) != "hello" {
		t.Fatalf("restored content = %q, %v", contents, err)
	}
}

func TestSymbolicLinkCannotEscapeRoot(t *testing.T) {
	base := t.TempDir()
	rootPath := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside.txt")
	if err := os.Mkdir(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootPath, "link.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	manager, err := New(filepath.Join(base, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	root := model.Root{ID: 1, Path: rootPath}
	if _, err := manager.Open(root, "link.txt"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("open symlink error = %v", err)
	}
	if err := manager.Copy(root, "link.txt", root, "copy.txt"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("copy symlink error = %v", err)
	}
	entries, err := manager.List(root, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Kind != "symlink" {
		t.Fatalf("symlink list entry = %#v", entries)
	}
}

func TestManagedRootCannotBeReplacedBySymlink(t *testing.T) {
	base := t.TempDir()
	rootPath := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(base, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	moved := filepath.Join(base, "old-root")
	if err := os.Rename(rootPath, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, rootPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := manager.List(model.Root{ID: 1, Path: rootPath}, "."); !errors.Is(err, ErrSymlink) {
		t.Fatalf("replaced root error = %v", err)
	}
}
