package store

import (
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
