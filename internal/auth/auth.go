package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	"server-file-manager/internal/model"
	"server-file-manager/internal/store"
)

const (
	SessionCookie = "sfm_session"
	SessionTTL    = 12 * time.Hour
)

var ErrInvalidCredentials = errors.New("invalid username or password")

func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(b), err
}

func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < 12 {
		return errors.New("密码至少需要 12 个字符")
	}
	if len(password) > 72 {
		return errors.New("密码不能超过 72 个字节")
	}
	return nil
}

func VerifyPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func NewOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

type Session struct {
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

func CreateSession(db *store.Store, userID int64) (Session, error) {
	token, err := NewOpaqueToken()
	if err != nil {
		return Session{}, err
	}
	csrf, err := NewOpaqueToken()
	if err != nil {
		return Session{}, err
	}
	expires := time.Now().UTC().Add(SessionTTL)
	if err := db.CreateSession(TokenHash(token), csrf, userID, expires); err != nil {
		return Session{}, err
	}
	return Session{Token: token, CSRFToken: csrf, ExpiresAt: expires}, nil
}

func Authenticate(db *store.Store, token string) (model.User, string, error) {
	if token == "" {
		return model.User{}, "", ErrInvalidCredentials
	}
	u, csrf, expires, err := db.Session(TokenHash(token))
	if err != nil {
		return model.User{}, "", err
	}
	if !u.Active || time.Now().After(expires) {
		_ = db.DeleteSession(TokenHash(token))
		return model.User{}, "", ErrInvalidCredentials
	}
	return u, csrf, nil
}

func ValidateUsername(username string) error {
	username = strings.TrimSpace(username)
	if !utf8.ValidString(username) || utf8.RuneCountInString(username) < 3 || utf8.RuneCountInString(username) > 64 || len(username) > 192 {
		return fmt.Errorf("用户名长度必须为 3 到 64 个字符")
	}
	for _, r := range username {
		if !(r == '_' || r == '-' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= 0x4e00 && r <= 0x9fff) {
			return errors.New("用户名只能包含中英文、数字、点、下划线和连字符")
		}
	}
	return nil
}
