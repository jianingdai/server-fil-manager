package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"server-file-manager/internal/filemanager"
	"server-file-manager/internal/model"
	"server-file-manager/internal/store"
)

func TestReconcileInterruptedRestorePreservesTrashCopy(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	db, err := store.Open(filepath.Join(dataDir, "manager.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	files, err := filemanager.New(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()

	user, err := db.CreateUser("worker", "unused-test-hash", model.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(base, "shared")
	if err := os.Mkdir(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := db.CreateRoot("Shared", rootPath, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	storedPath := filepath.Join(dataDir, "trash", "item-1")
	if err := os.WriteFile(storedPath, []byte("recoverable"), 0600); err != nil {
		t.Fatal(err)
	}
	entry := model.TrashEntry{ID: "item-1", RootID: root.ID, OriginalPath: "report.txt", Name: "report.txt", DeletedBy: user.ID, DeletedAt: time.Now().UTC()}
	if err := db.CreateTrash(entry, "trash/item-1"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetTrashReady(entry.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.SetTrashRestoring(entry.ID); err != nil {
		t.Fatal(err)
	}

	if err := reconcileTrash(db, files); err != nil {
		t.Fatal(err)
	}
	_, stored, err := db.Trash(entry.ID)
	if err != nil || stored != "trash/item-1" {
		t.Fatalf("reconciled trash entry stored=%q err=%v", stored, err)
	}
	if got, err := os.ReadFile(storedPath); err != nil || string(got) != "recoverable" {
		t.Fatalf("reconciled trash contents=%q err=%v", got, err)
	}
}
