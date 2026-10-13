package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"server-file-manager/internal/model"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound     = errors.New("record not found")
	ErrRootHasTrash = errors.New("root has recoverable trash entries")
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("secure data directory: %w", err)
	}
	dsn := (&url.URL{Scheme: "file", Path: abs}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	for _, statement := range []string{"PRAGMA foreign_keys = ON", "PRAGMA journal_mode = WAL", "PRAGMA busy_timeout = 5000"} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			return nil, fmt.Errorf("configure sqlite: %w", err)
		}
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(abs, 0600); err != nil {
		db.Close()
		return nil, fmt.Errorf("secure sqlite database: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','user')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS storage_roots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  canonical_path TEXT NOT NULL UNIQUE,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_root_permissions (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  root_id INTEGER NOT NULL REFERENCES storage_roots(id) ON DELETE CASCADE,
  can_list INTEGER NOT NULL DEFAULT 0 CHECK (can_list IN (0,1)),
  can_download INTEGER NOT NULL DEFAULT 0 CHECK (can_download IN (0,1)),
  can_upload INTEGER NOT NULL DEFAULT 0 CHECK (can_upload IN (0,1)),
  can_create_dir INTEGER NOT NULL DEFAULT 0 CHECK (can_create_dir IN (0,1)),
  can_rename INTEGER NOT NULL DEFAULT 0 CHECK (can_rename IN (0,1)),
  can_delete INTEGER NOT NULL DEFAULT 0 CHECK (can_delete IN (0,1)),
  can_copy INTEGER NOT NULL DEFAULT 0 CHECK (can_copy IN (0,1)),
  can_move INTEGER NOT NULL DEFAULT 0 CHECK (can_move IN (0,1)),
  can_search INTEGER NOT NULL DEFAULT 0 CHECK (can_search IN (0,1)),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, root_id)
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  csrf_token TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS trash_entries (
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
CREATE INDEX IF NOT EXISTS trash_user_idx ON trash_entries(deleted_by, deleted_at);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  root_id INTEGER REFERENCES storage_roots(id) ON DELETE SET NULL,
  path TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`
	// schema_migrations is declared in the migration string so fresh databases have
	// an explicit version marker; CREATE TABLE IF NOT EXISTS makes startup repeatable.
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("apply database schema: %w", err)
	}
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(1, ?)`, stamp(time.Now())); err != nil {
		return err
	}
	var version int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		return err
	}
	if version < 2 {
		if err := s.migrateTrashDeletedByNullable(); err != nil {
			return fmt.Errorf("migrate database to v2: %w", err)
		}
	}
	return nil
}

func (s *Store) migrateTrashDeletedByNullable() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []string{
		`DROP INDEX IF EXISTS trash_user_idx`,
		`ALTER TABLE trash_entries RENAME TO trash_entries_v1`,
		`CREATE TABLE trash_entries (
  id TEXT PRIMARY KEY,
  root_id INTEGER NOT NULL REFERENCES storage_roots(id) ON DELETE RESTRICT,
  original_path TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  name TEXT NOT NULL,
  deleted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  deleted_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ready' CHECK (status IN ('pending','ready','restoring','purging','restored','purged')),
  restored_at TEXT,
  purged_at TEXT
)`,
		`INSERT INTO trash_entries(id,root_id,original_path,stored_path,name,deleted_by,deleted_at,status,restored_at,purged_at)
 SELECT id,root_id,original_path,stored_path,name,deleted_by,deleted_at,status,restored_at,purged_at FROM trash_entries_v1`,
		`DROP TABLE trash_entries_v1`,
		`CREATE INDEX trash_user_idx ON trash_entries(deleted_by, deleted_at)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(2, ?)`, stamp(time.Now())); err != nil {
		return err
	}
	return tx.Commit()
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func parseStamp(v string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, v)
	return t
}

func (s *Store) UserCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) ActiveAdminCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM users WHERE role='admin' AND active=1`).Scan(&n)
	return n, err
}

func (s *Store) CreateUser(username, passwordHash, role string) (model.User, error) {
	now := stamp(time.Now())
	res, err := s.db.Exec(`INSERT INTO users(username,password_hash,role,active,created_at,updated_at) VALUES(?,?,?,1,?,?)`, username, passwordHash, role, now, now)
	if err != nil {
		return model.User{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.User{}, err
	}
	return model.User{ID: id, Username: username, Role: role, Active: true, CreatedAt: parseStamp(now)}, nil
}

func (s *Store) UserByUsername(username string) (model.User, string, error) {
	var u model.User
	var hash, created string
	var active int
	err := s.db.QueryRow(`SELECT id,username,password_hash,role,active,created_at FROM users WHERE username=?`, username).Scan(&u.ID, &u.Username, &hash, &u.Role, &active, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return u, "", ErrNotFound
	}
	if err != nil {
		return u, "", err
	}
	u.Active = active == 1
	u.CreatedAt = parseStamp(created)
	return u, hash, nil
}

func (s *Store) UserByID(id int64) (model.User, error) {
	var u model.User
	var active int
	var created string
	err := s.db.QueryRow(`SELECT id,username,role,active,created_at FROM users WHERE id=?`, id).Scan(&u.ID, &u.Username, &u.Role, &active, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	if err != nil {
		return u, err
	}
	u.Active, u.CreatedAt = active == 1, parseStamp(created)
	return u, nil
}

func (s *Store) DeleteUser(id int64) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE id=? AND role='user'`, id)
	return requireChanged(res, err)
}

func (s *Store) Users() ([]model.User, error) {
	rows, err := s.db.Query(`SELECT id,username,role,active,created_at FROM users ORDER BY username COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		var u model.User
		var active int
		var created string
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &active, &created); err != nil {
			return nil, err
		}
		u.Active, u.CreatedAt = active == 1, parseStamp(created)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) SetUserActive(id int64, active bool) error {
	v := 0
	if active {
		v = 1
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE users SET active=?,updated_at=? WHERE id=?`, v, stamp(time.Now()), id)
	if err = requireChanged(res, err); err != nil {
		_ = tx.Rollback()
		return err
	}
	if !active {
		if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id=?`, id); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SetPassword(id int64, passwordHash string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE users SET password_hash=?,updated_at=? WHERE id=?`, passwordHash, stamp(time.Now()), id)
	if err = requireChanged(res, err); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id=?`, id); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) SetRole(id int64, role string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE users SET role=?,updated_at=? WHERE id=?`, role, stamp(time.Now()), id)
	if err = requireChanged(res, err); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id=?`, id); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func requireChanged(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) CreateSession(tokenHash, csrf string, userID int64, expires time.Time) error {
	_, err := s.db.Exec(`INSERT INTO sessions(token_hash,csrf_token,user_id,created_at,expires_at) VALUES(?,?,?,?,?)`, tokenHash, csrf, userID, stamp(time.Now()), stamp(expires))
	return err
}

func (s *Store) Session(tokenHash string) (model.User, string, time.Time, error) {
	var u model.User
	var csrf, exp, created string
	var active int
	err := s.db.QueryRow(`SELECT u.id,u.username,u.role,u.active,u.created_at,s.csrf_token,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, tokenHash).Scan(&u.ID, &u.Username, &u.Role, &active, &created, &csrf, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return u, "", time.Time{}, ErrNotFound
	}
	if err != nil {
		return u, "", time.Time{}, err
	}
	u.Active, u.CreatedAt = active == 1, parseStamp(created)
	return u, csrf, parseStamp(exp), nil
}

func (s *Store) DeleteSession(tokenHash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}
func (s *Store) DeleteUserSessions(id int64) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id=?`, id)
	return err
}
func (s *Store) DeleteExpiredSessions(now time.Time) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, stamp(now))
	return err
}

func (s *Store) CreateRoot(name, canonical string, actor int64) (model.Root, error) {
	now := stamp(time.Now())
	res, err := s.db.Exec(`INSERT INTO storage_roots(name,canonical_path,active,created_by,created_at) VALUES(?,?,1,?,?)`, name, canonical, actor, now)
	if err != nil {
		return model.Root{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.Root{}, err
	}
	return model.Root{ID: id, Name: name, Path: canonical, Active: true, CreatedAt: parseStamp(now)}, nil
}

func scanRoot(row interface{ Scan(...any) error }) (model.Root, error) {
	var r model.Root
	var active int
	var created string
	err := row.Scan(&r.ID, &r.Name, &r.Path, &active, &created)
	r.Active = active == 1
	r.CreatedAt = parseStamp(created)
	return r, err
}

const rootColumns = `id,name,canonical_path,active,created_at`

func (s *Store) Root(id int64) (model.Root, error) {
	r, err := scanRoot(s.db.QueryRow(`SELECT `+rootColumns+` FROM storage_roots WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}
func (s *Store) Roots(activeOnly bool) ([]model.Root, error) {
	q := `SELECT ` + rootColumns + ` FROM storage_roots`
	if activeOnly {
		q += ` WHERE active=1`
	}
	q += ` ORDER BY name COLLATE NOCASE`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Root
	for rows.Next() {
		r, e := scanRoot(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) SetRootActive(id int64, active bool) error {
	v := 0
	if active {
		v = 1
	}
	res, err := s.db.Exec(`UPDATE storage_roots SET active=? WHERE id=?`, v, id)
	return requireChanged(res, err)
}

func (s *Store) DeleteRoot(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var pending int
	if err := tx.QueryRow(`SELECT count(*) FROM trash_entries WHERE root_id=? AND status IN ('pending','ready','restoring','purging')`, id).Scan(&pending); err != nil {
		return err
	}
	if pending > 0 {
		return ErrRootHasTrash
	}
	if _, err := tx.Exec(`DELETE FROM trash_entries WHERE root_id=? AND status IN ('restored','purged')`, id); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM storage_roots WHERE id=?`, id)
	if err = requireChanged(res, err); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetPermissions(userID, rootID int64, p model.Permissions) error {
	vals := []any{userID, rootID, boolInt(p.List), boolInt(p.Download), boolInt(p.Upload), boolInt(p.CreateDir), boolInt(p.Rename), boolInt(p.Delete), boolInt(p.Copy), boolInt(p.Move), boolInt(p.Search), stamp(time.Now())}
	_, err := s.db.Exec(`INSERT INTO user_root_permissions(user_id,root_id,can_list,can_download,can_upload,can_create_dir,can_rename,can_delete,can_copy,can_move,can_search,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id,root_id) DO UPDATE SET can_list=excluded.can_list,can_download=excluded.can_download,can_upload=excluded.can_upload,can_create_dir=excluded.can_create_dir,can_rename=excluded.can_rename,can_delete=excluded.can_delete,can_copy=excluded.can_copy,can_move=excluded.can_move,can_search=excluded.can_search,updated_at=excluded.updated_at`, vals...)
	return err
}

func (s *Store) ReplacePermissions(userID int64, roots []model.Root, provided map[int64]model.Permissions) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, root := range roots {
		p := provided[root.ID]
		if !root.Active {
			p = model.Permissions{}
		}
		vals := []any{userID, root.ID, boolInt(p.List), boolInt(p.Download), boolInt(p.Upload), boolInt(p.CreateDir), boolInt(p.Rename), boolInt(p.Delete), boolInt(p.Copy), boolInt(p.Move), boolInt(p.Search), stamp(time.Now())}
		_, err = tx.Exec(`INSERT INTO user_root_permissions(user_id,root_id,can_list,can_download,can_upload,can_create_dir,can_rename,can_delete,can_copy,can_move,can_search,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id,root_id) DO UPDATE SET can_list=excluded.can_list,can_download=excluded.can_download,can_upload=excluded.can_upload,can_create_dir=excluded.can_create_dir,can_rename=excluded.can_rename,can_delete=excluded.can_delete,can_copy=excluded.can_copy,can_move=excluded.can_move,can_search=excluded.can_search,updated_at=excluded.updated_at`, vals...)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func (s *Store) Permission(userID, rootID int64) (model.Permissions, error) {
	var p model.Permissions
	var a, b, c, d, e, f, g, h, i int
	err := s.db.QueryRow(`SELECT can_list,can_download,can_upload,can_create_dir,can_rename,can_delete,can_copy,can_move,can_search FROM user_root_permissions WHERE user_id=? AND root_id=?`, userID, rootID).Scan(&a, &b, &c, &d, &e, &f, &g, &h, &i)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	p = model.Permissions{List: a == 1, Download: b == 1, Upload: c == 1, CreateDir: d == 1, Rename: e == 1, Delete: f == 1, Copy: g == 1, Move: h == 1, Search: i == 1}
	return p, nil
}

func (s *Store) UserGrants(userID int64) ([]model.RootGrant, error) {
	rows, err := s.db.Query(`SELECT r.id,r.name,r.canonical_path,r.active,r.created_at,p.can_list,p.can_download,p.can_upload,p.can_create_dir,p.can_rename,p.can_delete,p.can_copy,p.can_move,p.can_search FROM storage_roots r JOIN user_root_permissions p ON p.root_id=r.id WHERE p.user_id=? AND r.active=1 AND (p.can_list=1 OR p.can_download=1 OR p.can_upload=1 OR p.can_create_dir=1 OR p.can_rename=1 OR p.can_delete=1 OR p.can_copy=1 OR p.can_move=1 OR p.can_search=1) ORDER BY r.name COLLATE NOCASE`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.RootGrant
	for rows.Next() {
		var g model.RootGrant
		var active int
		var created string
		var bits [9]int
		if err := rows.Scan(&g.Root.ID, &g.Root.Name, &g.Root.Path, &active, &created, &bits[0], &bits[1], &bits[2], &bits[3], &bits[4], &bits[5], &bits[6], &bits[7], &bits[8]); err != nil {
			return nil, err
		}
		g.Root.Active = active == 1
		g.Root.CreatedAt = parseStamp(created)
		g.Permissions = model.Permissions{List: bits[0] == 1, Download: bits[1] == 1, Upload: bits[2] == 1, CreateDir: bits[3] == 1, Rename: bits[4] == 1, Delete: bits[5] == 1, Copy: bits[6] == 1, Move: bits[7] == 1, Search: bits[8] == 1}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) CreateTrash(e model.TrashEntry, storedPath string) error {
	_, err := s.db.Exec(`INSERT INTO trash_entries(id,root_id,original_path,stored_path,name,deleted_by,deleted_at,status) VALUES(?,?,?,?,?,?,?,'pending')`, e.ID, e.RootID, e.OriginalPath, storedPath, e.Name, e.DeletedBy, stamp(e.DeletedAt))
	return err
}
func (s *Store) Trash(id string) (model.TrashEntry, string, error) {
	var e model.TrashEntry
	var p, deleted string
	err := s.db.QueryRow(`SELECT t.id,t.root_id,r.name,t.original_path,t.name,COALESCE(t.deleted_by,0),t.deleted_at,t.stored_path FROM trash_entries t JOIN storage_roots r ON r.id=t.root_id WHERE t.id=? AND t.status='ready' AND t.restored_at IS NULL AND t.purged_at IS NULL`, id).Scan(&e.ID, &e.RootID, &e.RootName, &e.OriginalPath, &e.Name, &e.DeletedBy, &deleted, &p)
	if errors.Is(err, sql.ErrNoRows) {
		return e, "", ErrNotFound
	}
	if err != nil {
		return e, "", err
	}
	e.DeletedAt = parseStamp(deleted)
	return e, p, nil
}
func (s *Store) TrashEntries(actor int64, admin bool) ([]model.TrashEntry, error) {
	q := `SELECT t.id,t.root_id,r.name,t.original_path,t.name,COALESCE(t.deleted_by,0),t.deleted_at FROM trash_entries t JOIN storage_roots r ON r.id=t.root_id WHERE t.status='ready' AND t.restored_at IS NULL AND t.purged_at IS NULL`
	args := []any{}
	if !admin {
		q += ` AND t.deleted_by=? AND r.active=1 AND EXISTS (
      SELECT 1 FROM user_root_permissions p
      WHERE p.user_id=? AND p.root_id=t.root_id AND p.can_upload=1
    )`
		args = append(args, actor, actor)
	}
	q += ` ORDER BY t.deleted_at DESC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.TrashEntry
	for rows.Next() {
		var e model.TrashEntry
		var when string
		if err := rows.Scan(&e.ID, &e.RootID, &e.RootName, &e.OriginalPath, &e.Name, &e.DeletedBy, &when); err != nil {
			return nil, err
		}
		e.DeletedAt = parseStamp(when)
		out = append(out, e)
	}
	return out, rows.Err()
}
func (s *Store) MarkRestored(id string) error {
	res, err := s.db.Exec(`UPDATE trash_entries SET status='restored',restored_at=? WHERE id=? AND restored_at IS NULL AND purged_at IS NULL`, stamp(time.Now()), id)
	return requireChanged(res, err)
}
func (s *Store) MarkPurged(id string) error {
	res, err := s.db.Exec(`UPDATE trash_entries SET status='purged',purged_at=? WHERE id=? AND purged_at IS NULL`, stamp(time.Now()), id)
	return requireChanged(res, err)
}
func (s *Store) SetTrashReady(id string) error {
	res, err := s.db.Exec(`UPDATE trash_entries SET status='ready' WHERE id=? AND status='pending'`, id)
	return requireChanged(res, err)
}
func (s *Store) SetTrashRestoring(id string) error {
	res, err := s.db.Exec(`UPDATE trash_entries SET status='restoring' WHERE id=? AND status='ready'`, id)
	return requireChanged(res, err)
}
func (s *Store) ResetTrashReady(id string) error {
	res, err := s.db.Exec(`UPDATE trash_entries SET status='ready' WHERE id=? AND status IN ('restoring','purging')`, id)
	return requireChanged(res, err)
}
func (s *Store) SetTrashPurging(id string) error {
	res, err := s.db.Exec(`UPDATE trash_entries SET status='purging' WHERE id=? AND status='ready'`, id)
	return requireChanged(res, err)
}
func (s *Store) DeleteTrashRecord(id string) error {
	_, err := s.db.Exec(`DELETE FROM trash_entries WHERE id=? AND status='pending'`, id)
	return err
}

type PendingTrash struct {
	ID                               string
	RootID                           int64
	OriginalPath, StoredPath, Status string
}

func (s *Store) PendingTrashEntries() ([]PendingTrash, error) {
	rows, err := s.db.Query(`SELECT id,root_id,original_path,stored_path,status FROM trash_entries WHERE status IN ('pending','restoring','purging')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingTrash
	for rows.Next() {
		var e PendingTrash
		if err := rows.Scan(&e.ID, &e.RootID, &e.OriginalPath, &e.StoredPath, &e.Status); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Audit(actor *int64, action string, rootID *int64, path, result string) {
	_, _ = s.db.Exec(`INSERT INTO audit_logs(actor_id,action,root_id,path,result,created_at) VALUES(?,?,?,?,?,?)`, actor, action, rootID, path, result, stamp(time.Now()))
}
