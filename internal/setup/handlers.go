package setup

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/auth"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/db"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/headscale"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/users"
)

//go:embed templates/*.html
var templateFS embed.FS

const (
	cookieSetup = "lss_setup"
	cookieCSRF  = "lss_csrf"
	settingDone = "setup_complete"

	recoveryCodeCount = 10
	totpIssuer        = "LSS Headscale Dashboard"
)

type Handler struct {
	db     *sql.DB
	signer *auth.SetupSigner
	log    *slog.Logger
	tmpl   *template.Template
}

func New(d *sql.DB, signer *auth.SetupSigner, log *slog.Logger) (*Handler, error) {
	t, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Handler{db: d, signer: signer, log: log, tmpl: t}, nil
}

// IsComplete reads the setup_complete flag from the settings table.
func IsComplete(d *sql.DB) (bool, error) {
	v, ok, err := db.GetSetting(d, settingDone)
	if err != nil || !ok {
		return false, err
	}
	return v == "true", nil
}

func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /setup", h.adminForm)
	mux.HandleFunc("POST /setup", h.createAdmin)
	mux.HandleFunc("POST /setup/totp", h.verifyTOTP)
	mux.HandleFunc("GET /setup/done", h.done)
	mux.HandleFunc("POST /setup/test-headscale", h.testHeadscale)
}

// ------- helpers -------

func (h *Handler) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		h.log.Error("render template", "name", name, "err", err)
	}
}

func (h *Handler) renderPage(w http.ResponseWriter, body string, data any) {
	if err := h.tmpl.ExecuteTemplate(w, body, data); err != nil {
		// Compose with base by executing both templates in order — actually we want
		// to render via the "base" template which references "content"/"title" defined
		// in the body template. html/template treats all parsed files as one template
		// set, so we just execute "base" and the right blocks resolve from `body`.
		h.log.Error("render", "body", body, "err", err)
	}
}

// renderWith renders the layout. The body template (admin.html, totp.html, done.html)
// must define `content` and `title` blocks; "base" template references them.
func (h *Handler) renderWith(w http.ResponseWriter, body string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Clone the template set so re-defining blocks for this request doesn't mutate state.
	t, err := h.tmpl.Clone()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Parse the chosen body template last to ensure its `define`s win.
	if _, err := t.ParseFS(templateFS, "templates/"+body); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		h.log.Error("render", "body", body, "err", err)
	}
}

func (h *Handler) ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(cookieCSRF); err == nil && len(c.Value) >= 24 {
		return c.Value
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieCSRF,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600,
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

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ------- handlers -------

type adminFormData struct {
	Error string
	CSRF  string
	Form  struct {
		Username string
		Email    string
	}
}

func (h *Handler) adminForm(w http.ResponseWriter, r *http.Request) {
	tok := h.ensureCSRF(w, r)
	h.renderWith(w, "admin.html", adminFormData{CSRF: tok})
}

func (h *Handler) createAdmin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "csrf check failed", http.StatusForbidden)
		return
	}

	var data adminFormData
	data.CSRF = h.ensureCSRF(w, r)
	data.Form.Username = strings.TrimSpace(r.FormValue("username"))
	data.Form.Email = strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	confirm := r.FormValue("password_confirm")

	switch {
	case len(data.Form.Username) < 3:
		data.Error = "Username must be at least 3 characters."
	case data.Form.Email == "" || !strings.Contains(data.Form.Email, "@"):
		data.Error = "A valid email is required."
	case len(password) < 12:
		data.Error = "Password must be at least 12 characters."
	case password != confirm:
		data.Error = "Passwords do not match."
	}
	if data.Error != "" {
		h.renderWith(w, "admin.html", data)
		return
	}

	uid, err := users.CreateAdmin(h.db, data.Form.Username, data.Form.Email, password)
	if err != nil {
		if errors.Is(err, users.ErrAlreadyExists) {
			data.Error = "An admin user already exists. Setup is in progress on another session."
			h.renderWith(w, "admin.html", data)
			return
		}
		h.log.Error("create admin", "err", err)
		data.Error = "Internal error creating user."
		h.renderWith(w, "admin.html", data)
		return
	}

	// Generate TOTP + recovery codes.
	secret, qrPNG, err := auth.GenerateTOTP(totpIssuer, data.Form.Email)
	if err != nil {
		h.log.Error("generate totp", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := users.StoreTOTPSecret(h.db, uid, secret); err != nil {
		h.log.Error("store totp", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	codes, err := auth.GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		h.log.Error("generate recovery codes", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = auth.HashRecoveryCode(c)
	}
	if err := users.StoreRecoveryCodes(h.db, uid, hashes); err != nil {
		h.log.Error("store recovery codes", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Set setup cookie carrying the pending user id.
	http.SetCookie(w, &http.Cookie{
		Name:     cookieSetup,
		Value:    h.signer.Sign(uid),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   1800,
	})

	h.log.Info("admin created", "user_id", uid, "username", data.Form.Username)

	// Render the TOTP page directly — recovery codes are shown ONCE and never persisted in plaintext.
	type totpPage struct {
		QRBase64      string
		SecretGrouped string
		RecoveryCodes []string
		CSRF          string
		Error         string
	}
	h.renderWith(w, "totp.html", totpPage{
		QRBase64:      base64.StdEncoding.EncodeToString(qrPNG),
		SecretGrouped: auth.FormatSecretForDisplay(secret),
		RecoveryCodes: codes,
		CSRF:          data.CSRF,
	})
}

func (h *Handler) verifyTOTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "csrf check failed", http.StatusForbidden)
		return
	}
	c, err := r.Cookie(cookieSetup)
	if err != nil {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	uid, err := h.signer.Verify(c.Value)
	if err != nil {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}

	secret, err := users.PendingTOTPSecret(h.db, uid)
	if err != nil {
		h.log.Error("pending totp lookup", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if !auth.VerifyTOTP(secret, code) {
		// Re-render TOTP page is messy because plaintext recovery codes are gone.
		// Send the user back with an error message — they can try again on this same form.
		h.log.Warn("auth: failed login", "user", "setup", "ip", clientIP(r), "stage", "totp_setup")
		http.Error(w, "Invalid code. Press back and try again. (Recovery codes shown previously remain valid.)", http.StatusBadRequest)
		return
	}
	if err := users.ConfirmTOTP(h.db, uid); err != nil {
		h.log.Error("confirm totp", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := db.SetSetting(h.db, settingDone, "true"); err != nil {
		h.log.Error("mark setup complete", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Clear setup cookie.
	http.SetCookie(w, &http.Cookie{Name: cookieSetup, Value: "", Path: "/", MaxAge: -1})

	h.log.Info("setup complete", "user_id", uid)
	http.Redirect(w, r, "/setup/done", http.StatusSeeOther)
}

func (h *Handler) done(w http.ResponseWriter, r *http.Request) {
	type doneData struct{ Username string }
	var d doneData
	row := h.db.QueryRow(`SELECT username FROM users WHERE is_admin = 1 ORDER BY id LIMIT 1`)
	_ = row.Scan(&d.Username)
	h.renderWith(w, "done.html", d)
}

// testHeadscale: JSON endpoint that dial-tests a Headscale gRPC config.
// Used by the (future) wizard step 3 UI; reachable while setup is incomplete only.
func (h *Handler) testHeadscale(w http.ResponseWriter, r *http.Request) {
	complete, _ := IsComplete(h.db)
	if complete {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Mode       string `json:"mode"`
		SocketPath string `json:"socket_path"`
		Address    string `json:"address"`
		TLS        bool   `json:"tls"`
		APIKey     string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "bad json"})
		return
	}
	cfg := headscale.Config{
		Mode:       headscale.Mode(req.Mode),
		SocketPath: req.SocketPath,
		Address:    req.Address,
		TLS:        req.TLS,
		APIKey:     req.APIKey,
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	if err := headscale.TestConnection(ctx, cfg); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
