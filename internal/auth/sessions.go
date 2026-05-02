package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

const (
	SessionCookieName = "lss_session"
	SessionDuration   = 12 * time.Hour
)

type Session struct {
	ID        string
	UserID    int64
	IP        string
	UserAgent string
	ExpiresAt time.Time
}

var ErrSessionNotFound = errors.New("session not found or expired")

func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func CreateSession(d *sql.DB, userID int64, ip, ua string) (*Session, error) {
	id, err := newSessionID()
	if err != nil {
		return nil, err
	}
	exp := time.Now().Add(SessionDuration)
	_, err = d.Exec(`
		INSERT INTO sessions (id, user_id, ip, user_agent, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, id, userID, ip, ua, exp)
	if err != nil {
		return nil, err
	}
	return &Session{ID: id, UserID: userID, IP: ip, UserAgent: ua, ExpiresAt: exp}, nil
}

func LookupSession(d *sql.DB, id string) (*Session, error) {
	s := &Session{ID: id}
	err := d.QueryRow(`
		SELECT user_id, ip, user_agent, expires_at FROM sessions
		WHERE id = ? AND expires_at > CURRENT_TIMESTAMP
	`, id).Scan(&s.UserID, &s.IP, &s.UserAgent, &s.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, ErrSessionNotFound
	}
	return s, err
}

func DeleteSession(d *sql.DB, id string) error {
	_, err := d.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func PurgeExpiredSessions(d *sql.DB) error {
	_, err := d.Exec(`DELETE FROM sessions WHERE expires_at <= CURRENT_TIMESTAMP`)
	return err
}

// SetSessionCookie writes the session cookie with appropriate flags.
// Secure is set when the request was forwarded over HTTPS.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.Header.Get("X-Forwarded-Proto") == "https",
		MaxAge:   int(SessionDuration.Seconds()),
	})
}

func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
