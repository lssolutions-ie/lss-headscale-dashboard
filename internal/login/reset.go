package login

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/audit"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/auth"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/settings"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/smtp"
)

const resetTokenTTL = time.Hour

// RegisterResetRoutes adds the forgot/reset endpoints to the public mux.
func (h *Handler) RegisterResetRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /forgot", h.forgotShow)
	mux.HandleFunc("POST /forgot", h.forgotSubmit)
	mux.HandleFunc("GET /reset/{token}", h.resetShow)
	mux.HandleFunc("POST /reset/{token}", h.resetSubmit)
}

type forgotData struct {
	page
	Sent bool
}

func (h *Handler) forgotShow(w http.ResponseWriter, r *http.Request) {
	d := forgotData{}
	d.CSRF = h.ensureCSRF(w, r)
	h.renderForgot(w, d)
}

func (h *Handler) forgotSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "csrf check failed", http.StatusForbidden)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	d := forgotData{}
	d.CSRF = h.ensureCSRF(w, r)
	d.Form.Username = username

	// Always show "if it exists, we sent it" so we don't leak which usernames are real.
	d.Sent = true

	user, err := lookupUser(h.db, username)
	if err != nil || user == nil || user.Email == "" {
		// Quietly succeed — no leak.
		h.renderForgot(w, d)
		return
	}

	smtpCfg, err := settings.GetSMTP(h.db)
	if err != nil || !smtpCfg.Enabled || smtpCfg.Host == "" {
		// SMTP not configured — log loudly so the operator notices.
		h.log.Warn("password reset requested but SMTP is not configured", "user", user.Username)
		h.renderForgot(w, d)
		return
	}

	token, hash, err := newResetToken()
	if err != nil {
		h.log.Error("password reset: token gen", "err", err)
		h.renderForgot(w, d)
		return
	}
	expires := time.Now().Add(resetTokenTTL)
	if _, err := h.db.Exec(
		`INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)`,
		user.ID, hash, expires,
	); err != nil {
		h.log.Error("password reset: insert", "err", err)
		h.renderForgot(w, d)
		return
	}

	mailer := smtp.New(smtpCfg)
	link := schemeFromRequest(r) + "://" + r.Host + "/reset/" + token
	body := "A password reset was requested for your LSS Headscale Dashboard account.\r\n\r\n" +
		"Open this link to choose a new password (valid for 1 hour):\r\n" +
		link + "\r\n\r\n" +
		"If you didn't request this, ignore this email — your password is unchanged.\r\n"
	if err := mailer.Send(user.Email, "LSS Headscale Dashboard password reset", body); err != nil {
		h.log.Error("password reset: send mail", "err", err, "to", user.Email)
		// Still show "sent" so we don't leak. Operator sees this in journald.
	} else {
		audit.Write(h.db, &user.ID, auth.ClientIP(r), audit.ActionPasswordChange, "reset_requested", nil)
	}
	h.renderForgot(w, d)
}

type resetData struct {
	page
	Token   string
	Done    bool
	Invalid bool
}

func (h *Handler) resetShow(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	d := resetData{Token: tok}
	d.CSRF = h.ensureCSRF(w, r)
	if _, err := lookupResetToken(h.db, tok); err != nil {
		d.Invalid = true
	}
	h.renderReset(w, d)
}

func (h *Handler) resetSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "csrf check failed", http.StatusForbidden)
		return
	}
	tok := r.PathValue("token")
	d := resetData{Token: tok}
	d.CSRF = h.ensureCSRF(w, r)

	row, err := lookupResetToken(h.db, tok)
	if err != nil {
		d.Invalid = true
		h.renderReset(w, d)
		return
	}
	newPw := r.FormValue("new_password")
	confirm := r.FormValue("confirm")
	if newPw != confirm {
		d.Error = "Passwords do not match."
		h.renderReset(w, d)
		return
	}
	if len(newPw) < 12 {
		d.Error = "Password must be at least 12 characters."
		h.renderReset(w, d)
		return
	}
	hash, err := auth.HashPassword(newPw)
	if err != nil {
		d.Error = "Internal error."
		h.renderReset(w, d)
		return
	}
	if _, err := h.db.Exec(`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, hash, row.UserID); err != nil {
		h.log.Error("reset: update password", "err", err)
		d.Error = "Internal error."
		h.renderReset(w, d)
		return
	}
	if _, err := h.db.Exec(`UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE id = ?`, row.ID); err != nil {
		h.log.Error("reset: mark used", "err", err)
	}
	// Invalidate every existing session — anything held by an attacker who
	// initiated the reset is now dead.
	_, _ = h.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, row.UserID)
	uid := row.UserID
	audit.Write(h.db, &uid, auth.ClientIP(r), audit.ActionPasswordChange, "reset_completed", nil)
	d.Done = true
	h.renderReset(w, d)
}

// ----- helpers -----

type resetRow struct {
	ID     int64
	UserID int64
}

// lookupResetToken returns the row for a still-valid (unexpired, unused) token.
func lookupResetToken(d *sql.DB, token string) (*resetRow, error) {
	hash := hashResetToken(token)
	r := &resetRow{}
	err := d.QueryRow(
		`SELECT id, user_id FROM password_resets
		 WHERE token_hash = ? AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP`,
		hash,
	).Scan(&r.ID, &r.UserID)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func newResetToken() (token, hash string, err error) {
	b := make([]byte, 24)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	hash = hashResetToken(token)
	return
}

func hashResetToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func schemeFromRequest(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-Proto"); x != "" {
		return x
	}
	if r.TLS != nil {
		return "https"
	}
	host := r.Host
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return "http"
	}
	return "https"
}

// renderForgot / renderReset reuse the existing base layout from dashboard.

func (h *Handler) renderForgot(w http.ResponseWriter, d forgotData) {
	h.renderBody(w, "forgot.html", d)
}

func (h *Handler) renderReset(w http.ResponseWriter, d resetData) {
	h.renderBody(w, "reset.html", d)
}
