package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
	"server-file-manager/internal/auth"
	"server-file-manager/internal/filemanager"
	"server-file-manager/internal/httpapi"
	"server-file-manager/internal/model"
	"server-file-manager/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "init-admin":
		return initAdmin(args[1:])
	case "user":
		return userCommand(args[1:])
	case "help", "-h", "--help":
		return usage()
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usageText)
	}
}

const usageText = `用法:
  server-file-manager init-admin [--data-dir DIR] [--username NAME]
  server-file-manager user set-role [--data-dir DIR] USERNAME admin|user
  server-file-manager serve [--listen :8080] [--data-dir DIR] [--tls-cert FILE --tls-key FILE]

serve 默认前台运行；程序不会自动创建默认账号或公开监听低位端口。`

func usage() error { fmt.Println(usageText); return nil }

func defaultDataDir() string {
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return filepath.Join(v, "server-file-manager")
	}
	u, err := user.Current()
	if err != nil {
		return filepath.Join(".", ".local", "share", "server-file-manager")
	}
	return filepath.Join(u.HomeDir, ".local", "share", "server-file-manager")
}

func openStore(dataDir string) (*store.Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dataDir, 0700); err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(dataDir, "manager.sqlite3"))
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "HTTP listen address; use an intranet address or high port")
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for SQLite data, sessions, and trash")
	tlsCert := fs.String("tls-cert", "", "TLS certificate PEM file")
	tlsKey := fs.String("tls-key", "", "TLS private key PEM file")
	secureCookie := fs.Bool("secure-cookie", false, "set Secure cookies when HTTPS is terminated by a trusted reverse proxy")
	maxUpload := fs.Int64("max-upload-bytes", 0, "maximum upload size in bytes; 0 means no application-level limit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("serve does not accept positional arguments")
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return errors.New("--tls-cert and --tls-key must be provided together")
	}
	if *maxUpload < 0 {
		return errors.New("--max-upload-bytes cannot be negative")
	}
	if _, portText, e := net.SplitHostPort(*listen); e == nil {
		if p, e := strconvPort(":" + portText); e == nil && p < 1024 {
			return errors.New("低于 1024 的端口需要系统管理员配置；请选择高位端口")
		}
	}
	db, err := openStore(*dataDir)
	if err != nil {
		return err
	}
	defer db.Close()
	count, err := db.UserCount()
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("尚无管理员账号，请先运行 init-admin")
	}
	files, err := filemanager.New(*dataDir)
	if err != nil {
		return err
	}
	defer files.Close()
	if err := reconcileTrash(db, files); err != nil {
		return fmt.Errorf("恢复回收站状态: %w", err)
	}
	_ = db.DeleteExpiredSessions(time.Now())
	publicHTTPS := *tlsCert != "" || *secureCookie
	api := httpapi.New(db, files, *dataDir, publicHTTPS, *maxUpload)
	protocol := "HTTP"
	if *tlsCert != "" {
		protocol = "HTTPS"
	} else if *secureCookie {
		protocol = "HTTP (HTTPS terminated by proxy)"
	}
	slog.Info("file manager started", "protocol", protocol, "listen", *listen, "data_dir", *dataDir)
	return httpapi.Run(*listen, *tlsCert, *tlsKey, api.Handler())
}

func strconvPort(address string) (int, error) {
	part := strings.TrimPrefix(address, ":")
	if part == "" {
		return 0, errors.New("missing port")
	}
	return strconv.Atoi(part)
}

func initAdmin(args []string) error {
	fs := flag.NewFlagSet("init-admin", flag.ContinueOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory")
	usernameFlag := fs.String("username", "", "administrator username")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("init-admin does not accept positional arguments")
	}
	username := strings.TrimSpace(*usernameFlag)
	reader := bufio.NewReader(os.Stdin)
	if username == "" {
		fmt.Print("管理员用户名: ")
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		username = strings.TrimSpace(line)
	}
	if err := auth.ValidateUsername(username); err != nil {
		return err
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("请在交互式终端运行 init-admin，以便隐藏密码输入")
	}
	fmt.Print("管理员密码（至少 12 个字节）: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}
	fmt.Print("再次输入密码: ")
	confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}
	if string(password) != string(confirm) {
		return errors.New("两次输入的密码不一致")
	}
	hash, err := auth.HashPassword(string(password))
	if err != nil {
		return err
	}
	db, err := openStore(*dataDir)
	if err != nil {
		return err
	}
	defer db.Close()
	count, err := db.UserCount()
	if err != nil {
		return err
	}
	if count != 0 {
		return errors.New("数据库已有用户；不能再次初始化首位管理员")
	}
	if _, err := db.CreateUser(username, hash, model.RoleAdmin); err != nil {
		return err
	}
	fmt.Printf("管理员 %q 已创建。\n", username)
	return nil
}

func userCommand(args []string) error {
	if len(args) == 0 || args[0] != "set-role" {
		return errors.New("用法: server-file-manager user set-role [--data-dir DIR] USERNAME admin|user")
	}
	fs := flag.NewFlagSet("user set-role", flag.ContinueOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("用法: server-file-manager user set-role [--data-dir DIR] USERNAME admin|user")
	}
	username, role := fs.Arg(0), fs.Arg(1)
	if role != model.RoleAdmin && role != model.RoleUser {
		return errors.New("角色必须是 admin 或 user")
	}
	db, err := openStore(*dataDir)
	if err != nil {
		return err
	}
	defer db.Close()
	u, _, err := db.UserByUsername(username)
	if err != nil {
		return err
	}
	if u.Role == model.RoleAdmin && role == model.RoleUser {
		n, err := db.ActiveAdminCount()
		if err != nil {
			return err
		}
		if n <= 1 && u.Active {
			return errors.New("不能降级最后一个启用的管理员")
		}
	}
	if err := db.SetRole(u.ID, role); err != nil {
		return err
	}
	db.Audit(nil, "user.role", nil, username, role)
	fmt.Printf("用户 %q 的角色已设为 %s。\n", username, role)
	return nil
}

func reconcileTrash(db *store.Store, files *filemanager.Manager) error {
	items, err := db.PendingTrashEntries()
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Status == "pending" {
			// Prefer a visible duplicate in the rare crash window over deleting the
			// only recoverable copy of a user's file.
			if e := db.SetTrashReady(item.ID); e != nil {
				return e
			}
		} else if item.Status == "restoring" {
			hasStoredCopy, e := files.HasStored(item.StoredPath)
			if e != nil {
				return e
			}
			if hasStoredCopy {
				// A crash may have happened before or during restore. Keep the
				// stored copy and make it available again; duplicates are safer
				// than purging the only recoverable copy.
				if e := db.ResetTrashReady(item.ID); e != nil {
					return e
				}
			} else {
				// Restore removes the stored copy only after publishing the target.
				if e := db.MarkRestored(item.ID); e != nil {
					return e
				}
			}
		} else if item.Status == "purging" {
			if e := files.Purge(item.StoredPath); e != nil {
				return e
			}
			if e := db.MarkPurged(item.ID); e != nil {
				return e
			}
		}
	}
	return nil
}
