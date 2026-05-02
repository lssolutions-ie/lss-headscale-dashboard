package auth

import (
	"database/sql"
	"time"
)

const (
	MaxFailedAttempts = 5
	FailureWindow     = 10 * time.Minute
	LockoutDuration   = 15 * time.Minute
)

func RecordLoginFailure(d *sql.DB, username, ip string) error {
	_, err := d.Exec(`INSERT INTO auth_failures (username, ip) VALUES (?, ?)`, username, ip)
	return err
}

// IsLockedOut returns true if (username, ip) has had MaxFailedAttempts within FailureWindow,
// and the lockout has not yet aged out.
func IsLockedOut(d *sql.DB, username, ip string) (bool, error) {
	var n int
	err := d.QueryRow(`
		SELECT COUNT(*) FROM auth_failures
		WHERE username = ? AND ip = ? AND failed_at > datetime('now', ?)
	`, username, ip, "-"+FailureWindow.String()).Scan(&n)
	if err != nil {
		return false, err
	}
	if n >= MaxFailedAttempts {
		// Check the most recent failure to enforce lockout duration.
		var last time.Time
		err := d.QueryRow(`
			SELECT MAX(failed_at) FROM auth_failures WHERE username = ? AND ip = ?
		`, username, ip).Scan(&last)
		if err != nil {
			return false, err
		}
		if time.Since(last) < LockoutDuration {
			return true, nil
		}
	}
	return false, nil
}

func ClearLoginFailures(d *sql.DB, username, ip string) error {
	_, err := d.Exec(`DELETE FROM auth_failures WHERE username = ? AND ip = ?`, username, ip)
	return err
}

func PurgeOldAuthFailures(d *sql.DB) error {
	// Keep 24h of history for visibility / forensics.
	_, err := d.Exec(`DELETE FROM auth_failures WHERE failed_at < datetime('now', '-24 hours')`)
	return err
}
