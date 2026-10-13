package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"server-file-manager/internal/model"
)

func TestUsersPermissionsAndSessionsPersist(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "private-data")
	db, err := Open(filepath.Join(dataDir, "manager.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := db.CreateUser("admin", "hash", model.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	user, err := db.CreateUser("person", "hash", model.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	root, err := db.CreateRoot("Documents", filepath.Join(t.TempDir(), "docs"), admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	p := model.Permissions{List: true, Download: true, Upload: true, Delete: true, Copy: true, Move: true, Search: true}
	if err := db.SetPermissions(user.ID, root.ID, p); err != nil {
		t.Fatal(err)
	}
	got, err := db.Permission(user.ID, root.ID)
	if err != nil || got != p {
		t.Fatalf("permissions = %#v, %v", got, err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	if err := db.CreateSession("token-hash", "csrf", user.ID, expires); err != nil {
		t.Fatal(err)
	}
	gotUser, csrf, gotExpires, err := db.Session("token-hash")
	if err != nil || gotUser.ID != user.ID || csrf != "csrf" || !gotExpires.Equal(expires) {
		t.Fatalf("session = %#v %q %v %v", gotUser, csrf, gotExpires, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("data dir mode = %o", info.Mode().Perm())
	}
}

func TestV1MigrationPreservesTrashAndAllowsDeletingOwner(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "manager.sqlite3")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := db.CreateUser("admin", "hash", model.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	user, err := db.CreateUser("worker", "hash", model.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	root, err := db.CreateRoot("Shared", t.TempDir(), admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetPermissions(user.ID, root.ID, model.Permissions{List: true}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSession("worker-session", "csrf", user.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	entry := model.TrashEntry{ID: "retained-trash", RootID: root.ID, OriginalPath: "report.txt", Name: "report.txt", DeletedBy: user.ID, DeletedAt: time.Now().UTC()}
	if err := db.CreateTrash(entry, "trash/retained-trash"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetTrashReady(entry.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Recreate the v1 NOT NULL/RESTRICT definition to exercise a real upgrade.
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`PRAGMA foreign_keys=ON;
DROP INDEX IF EXISTS trash_user_idx;
ALTER TABLE trash_entries RENAME TO trash_entries_v2;
CREATE TABLE trash_entries (
 id TEXT PRIMARY KEY,
 root_id INTEGER NOT NULL REFERENCES storage_roots(id) ON DELETE RESTRICT,
 original_path TEXT NOT NULL,
 stored_path TEXT NOT NULL,
 name TEXT NOT NULL,
 deleted_by INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 deleted_at TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'ready' CHECK (status IN ('pending','ready','restoring','purging','restored','purged')),
 restored_at TEXT,
 purged_at TEXT
);
INSERT INTO trash_entries SELECT * FROM trash_entries_v2;
DROP TABLE trash_entries_v2;
CREATE INDEX trash_user_idx ON trash_entries(deleted_by, deleted_at);
DELETE FROM schema_migrations WHERE version=2;`)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.DeleteUser(user.ID); err != nil {
		t.Fatalf("delete regular user after migration: %v", err)
	}
	if _, _, _, err := db.Session("worker-session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted user's session remains: %v", err)
	}
	if _, err := db.Permission(user.ID, root.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted user's permission remains: %v", err)
	}
	entries, err := db.TrashEntries(0, true)
	if err != nil || len(entries) != 1 || entries[0].ID != entry.ID || entries[0].DeletedBy != 0 {
		t.Fatalf("trash after owner deletion = %#v, %v", entries, err)
	}
	if err := db.DeleteUser(admin.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("web delete operation accepted admin role: %v", err)
	}
	if _, err := db.CreateUser("worker", "replacement-hash", model.RoleUser); err != nil {
		t.Fatalf("deleted username was not released: %v", err)
	}
}

func TestDeleteRootBlocksRecoverableTrashAndLeavesFilesystem(t *testing.T) {
	shared := t.TempDir()
	file := filepath.Join(shared, "keep.txt")
	if err := os.WriteFile(file, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := Open(filepath.Join(t.TempDir(), "manager.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	admin, err := db.CreateUser("admin", "hash", model.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	user, err := db.CreateUser("worker", "hash", model.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	root, err := db.CreateRoot("Shared", shared, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetPermissions(user.ID, root.ID, model.Permissions{List: true}); err != nil {
		t.Fatal(err)
	}
	entry := model.TrashEntry{ID: "root-trash", RootID: root.ID, OriginalPath: "old.txt", Name: "old.txt", DeletedBy: user.ID, DeletedAt: time.Now().UTC()}
	if err := db.CreateTrash(entry, "trash/root-trash"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetTrashReady(entry.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteRoot(root.ID); !errors.Is(err, ErrRootHasTrash) {
		t.Fatalf("delete root with recoverable trash = %v", err)
	}
	if err := db.MarkPurged(entry.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteRoot(root.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Root(root.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("root registration remains: %v", err)
	}
	if _, err := db.Permission(user.ID, root.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("root permission remains: %v", err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("filesystem content was touched: %v", err)
	}
	var history int
	if err := db.db.QueryRow(`SELECT count(*) FROM trash_entries WHERE root_id=?`, root.ID).Scan(&history); err != nil || history != 0 {
		t.Fatalf("settled trash history rows=%d err=%v", history, err)
	}
}
