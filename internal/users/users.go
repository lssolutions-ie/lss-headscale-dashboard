package users

import (
	"database/sql"
	"errors"
	"time"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/auth"
)

type User struct {
	ID           int64
	Username     string
	Email        string
	PasswordHash string
	IsAdmin      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

var ErrAlreadyExists = errors.New("a user already exists")

// CreateAdmin inserts a new admin user. v1 supports a single admin created via
// the setup wizard; this returns ErrAlreadyExists if any user already exists.
func CreateAdmin(d *sql.DB, username, email, password string) (int64, error) {
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, err
	}
	if n > 0 {
		return 0, ErrAlreadyExists
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return 0, err
	}
	res, err := d.Exec(`
		INSERT INTO users (username, email, password_hash, is_admin)
		VALUES (?, ?, ?, 1)
	`, username, email, hash)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func GetByID(d *sql.DB, id int64) (*User, error) {
	u := &User{}
	err := d.QueryRow(`
		SELECT id, username, email, password_hash, is_admin, created_at, updated_at
		FROM users WHERE id = ?
	`, id).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func StoreTOTPSecret(d *sql.DB, userID int64, secret string) error {
	_, err := d.Exec(`
		INSERT INTO totp_secrets (user_id, secret) VALUES (?, ?)
	`, userID, secret)
	return err
}

// PendingTOTPSecret returns the most recent unconfirmed TOTP secret for a user.
func PendingTOTPSecret(d *sql.DB, userID int64) (string, error) {
	var s string
	err := d.QueryRow(`
		SELECT secret FROM totp_secrets
		WHERE user_id = ? AND confirmed_at IS NULL
		ORDER BY id DESC LIMIT 1
	`, userID).Scan(&s)
	return s, err
}

func ConfirmTOTP(d *sql.DB, userID int64) error {
	_, err := d.Exec(`
		UPDATE totp_secrets
		SET confirmed_at = CURRENT_TIMESTAMP
		WHERE user_id = ? AND confirmed_at IS NULL
	`, userID)
	return err
}

func StoreRecoveryCodes(d *sql.DB, userID int64, hashes []string) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, h := range hashes {
		if _, err := stmt.Exec(userID, h); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}
