package login

import (
	"database/sql"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/audit"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/auth"
)

//go:embed templates/*.html
var templateFS embed.FS

type Handler struct {
	db   *sql.DB
	log  *slog.Logger
	tmpl *template.Template
}

// New initializes the login handler. base is the layout template (e.g. dashboard's base.html)
// that defines the "base" template referenced by login.html.
func New(d *sql.DB, log *slog.Logger, baseFS embed.FS, basePattern string) (*Handler, error) {
	// The dashboard's other templates also live in baseFS and reference helper
	// funcs like `contains`; register them so ParseFS doesn't reject them.
	t := template.New("login").Funcs(template.FuncMap{
		"contains":  strings.Contains,
		"hasPrefix": strings.HasPrefix,
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "…"
		},
	})
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
	// POST-only (no GET) and CSRF-protected — keeps drive-by-image attacks
	// from logging the admin out via <img src="/logout">.
	mux.HandleFunc("POST /logout", h.logout)
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
	return auth.EnsureCSRFToken(w, r)
}

func (h *Handler) checkCSRF(r *http.Request) bool { return auth.CheckCSRFToken(r) }

func (h *Handler) render(w http.ResponseWriter, p page) {
	h.renderBody(w, "login.html", p)
}

// renderBody clones the parsed template set and re-parses the chosen body
// last, so that body's `content`/`title` blocks win for this single render.
// Without this, all login-package templates collide on `content`.
func (h *Handler) renderBody(w http.ResponseWriter, body string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, err := h.tmpl.Clone()
	if err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	if _, err := t.ParseFS(templateFS, "templates/"+body); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		h.log.Error("render", "body", body, "err", err)
	}
}

func (h *Handler) show(w http.ResponseWriter, r *http.Request) {
	tok := h.ensureCSRF(w, r)
	h.render(w, page{CSRF: tok})
}

func clientIP(r *http.Request) string { return auth.ClientIP(r) }

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
	if !h.checkCSRF(r) {
		http.Error(w, "csrf check failed", http.StatusForbidden)
		return
	}
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
