package login

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/audit"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/auth"
)

//go:embed templates/*.html
var templateFS embed.FS

const (
	cookieCSRF = "lss_csrf"
)

type Handler struct {
	db   *sql.DB
	log  *slog.Logger
	tmpl *template.Template
}

// New initializes the login handler. base is the layout template (e.g. dashboard's base.html)
// that defines the "base" template referenced by login.html.
func New(d *sql.DB, log *slog.Logger, baseFS embed.FS, basePattern string) (*Handler, error) {
	t := template.New("login")
	if _, err := t.ParseFS(baseFS, basePattern); err != nil {
		return nil, err
	}
	if _, err := t.ParseFS(templateFS, "templates/*.html"); err != nil {
		return nil, err
	}
	return &Handler{db: d, log: log, tmpl: t}, nil
}

func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", h.show)
	mux.HandleFunc("POST /login", h.submit)
	mux.HandleFunc("POST /logout", h.logout)
	mux.HandleFunc("GET /logout", h.logout)
}

type page struct {
	Error string
	CSRF  string
	Form  struct {
		Username string
	}
	// Fields below exist only to satisfy the shared base.html template
	// (which is also used by the authenticated dashboard).
	User   any
	Active string
	Flash  any
}

func (h *Handler) ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(cookieCSRF); err == nil && len(c.Value) >= 24 {
		return c.Value
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name: cookieCSRF, Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 3600,
	})
	return tok
}

func (h *Handler) checkCSRF(r *http.Request) bool {
	c, err := r.Cookie(cookieCSRF)
	if err != nil {
		return false
	}
	return r.FormValue("csrf") != "" && r.FormValue("csrf") == c.Value
}

func (h *Handler) render(w http.ResponseWriter, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "base", p); err != nil {
		h.log.Error("render login", "err", err)
	}
}

func (h *Handler) show(w http.ResponseWriter, r *http.Request) {
	tok := h.ensureCSRF(w, r)
	h.render(w, page{CSRF: tok})
}

func clientIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		// HAProxy/NGINX set the original IP at index 0.
		if i := strings.Index(x, ","); i >= 0 {
			return strings.TrimSpace(x[:i])
		}
		return strings.TrimSpace(x)
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "csrf check failed", http.StatusForbidden)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	code := strings.TrimSpace(r.FormValue("code"))
	ip := clientIP(r)

	var p page
	p.CSRF = h.ensureCSRF(w, r)
	p.Form.Username = username

	locked, err := auth.IsLockedOut(h.db, username, ip)
	if err != nil {
		h.log.Error("lockout check", "err", err)
		p.Error = "Internal error."
		h.render(w, p)
		return
	}
	if locked {
		h.log.Warn("auth: login locked", "user", username, "ip", ip)
		p.Error = "Too many failed attempts. Try again in 15 minutes."
		h.render(w, p)
		return
	}

	user, err := lookupUser(h.db, username)
	if err != nil {
		h.recordFailure(username, ip, "user not found")
		p.Error = "Invalid credentials or TOTP code."
		h.render(w, p)
		return
	}

	ok, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil || !ok {
		h.recordFailure(username, ip, "bad password")
		p.Error = "Invalid credentials or TOTP code."
		h.render(w, p)
		return
	}

	codeOK := false
	if len(code) == 6 {
		secret, err := getConfirmedTOTPSecret(h.db, user.ID)
		if err == nil && secret != "" {
			codeOK = auth.VerifyTOTP(secret, code)
		}
	}
	if !codeOK {
		// Maybe a recovery code (XXXX-XXXX-XXXX or XXXXXXXXXXXX).
		if isRecoveryCodeShape(code) {
			codeOK, _ = consumeRecoveryCode(h.db, user.ID, code)
		}
	}
	if !codeOK {
		h.recordFailure(username, ip, "bad totp")
		p.Error = "Invalid credentials or TOTP code."
		h.render(w, p)
		return
	}

	_ = auth.ClearLoginFailures(h.db, username, ip)

	session, err := auth.CreateSession(h.db, user.ID, ip, r.UserAgent())
	if err != nil {
		h.log.Error("create session", "err", err)
		p.Error = "Internal error."
		h.render(w, p)
		return
	}
	auth.SetSessionCookie(w, r, session.ID)

	uid := user.ID
	audit.Write(h.db, &uid, ip, audit.ActionLoginSuccess, user.Username, nil)
	h.log.Info("auth: login ok", "user", user.Username, "ip", ip)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.SessionCookieName); err == nil {
		s, err := auth.LookupSession(h.db, c.Value)
		if err == nil {
			audit.Write(h.db, &s.UserID, clientIP(r), audit.ActionLogout, "", nil)
			_ = auth.DeleteSession(h.db, c.Value)
		}
	}
	auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) recordFailure(username, ip, reason string) {
	_ = auth.RecordLoginFailure(h.db, username, ip)
	h.log.Warn("auth: failed login", "user", username, "ip", ip, "reason", reason)
	audit.Write(h.db, nil, ip, audit.ActionLoginFailure, username, map[string]any{"reason": reason})
}

// ----- DB helpers (kept here to avoid an import cycle with users package) -----

type loginUser struct {
	ID           int64
	Username     string
	Email        string
	PasswordHash string
}

func lookupUser(d *sql.DB, identifier string) (*loginUser, error) {
	u := &loginUser{}
	err := d.QueryRow(`
		SELECT id, username, email, password_hash FROM users
		WHERE username = ? OR email = ?
		LIMIT 1
	`, identifier, identifier).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func getConfirmedTOTPSecret(d *sql.DB, userID int64) (string, error) {
	var s string
	err := d.QueryRow(`
		SELECT secret FROM totp_secrets
		WHERE user_id = ? AND confirmed_at IS NOT NULL
		ORDER BY id DESC LIMIT 1
	`, userID).Scan(&s)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return s, err
}

func isRecoveryCodeShape(s string) bool {
	bare := strings.ToUpper(strings.ReplaceAll(s, "-", ""))
	return len(bare) == 12
}

func consumeRecoveryCode(d *sql.DB, userID int64, code string) (bool, error) {
	hash := auth.HashRecoveryCode(code)
	res, err := d.Exec(`
		UPDATE recovery_codes
		SET used_at = CURRENT_TIMESTAMP
		WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
	`, userID, hash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
