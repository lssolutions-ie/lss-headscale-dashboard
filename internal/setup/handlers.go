package setup

import (
	"context"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/auth"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/db"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/headscale"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/settings"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/users"
)

//go:embed templates/*.html
var templateFS embed.FS

const (
	cookieSetup = "lss_setup"
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
	mux.HandleFunc("GET /setup", h.guardSetup(h.adminForm))
	mux.HandleFunc("POST /setup", h.guardSetup(h.createAdmin))
	mux.HandleFunc("POST /setup/totp", h.guardSetup(h.verifyTOTP))
	mux.HandleFunc("GET /setup/smtp", h.guardSetup(h.smtpForm))
	mux.HandleFunc("POST /setup/smtp", h.guardSetup(h.smtpSubmit))
	mux.HandleFunc("GET /setup/headscale", h.guardSetup(h.headscaleForm))
	mux.HandleFunc("POST /setup/headscale", h.guardSetup(h.headscaleSubmit))
	mux.HandleFunc("GET /setup/done", h.done) // reachable AFTER setup_complete is set
	mux.HandleFunc("POST /setup/test-headscale", h.guardSetup(h.testHeadscale))
}

// guardSetup wraps a wizard handler so it only runs while setup_complete=false.
// Once setup is done, the wizard is closed for business and we redirect to /login.
func (h *Handler) guardSetup(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		complete, err := IsComplete(h.db)
		if err != nil {
			h.log.Error("read setup state", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if complete {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// ------- helpers -------

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

// CSRF + clientIP live in the auth package now (consolidated). These wrappers
// stay so the rest of the file reads naturally.
func (h *Handler) ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	return auth.EnsureCSRFToken(w, r)
}

func (h *Handler) checkCSRF(r *http.Request) bool { return auth.CheckCSRFToken(r) }

func clientIP(r *http.Request) string { return auth.ClientIP(r) }

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
	// Don't flip setup_complete yet — there are still SMTP and Headscale steps.
	// Keep the setup cookie too; harmless and re-issued by step 2 if needed.
	h.log.Info("setup step 1 complete — moving to SMTP", "user_id", uid)
	http.Redirect(w, r, "/setup/smtp", http.StatusSeeOther)
}

// ----- Step 2: SMTP -----

type smtpFormData struct {
	Error string
	CSRF  string
	Form  settings.SMTP
}

func (h *Handler) smtpForm(w http.ResponseWriter, r *http.Request) {
	d := smtpFormData{CSRF: h.ensureCSRF(w, r)}
	d.Form, _ = settings.GetSMTP(h.db)
	if d.Form.Port == 0 {
		d.Form.Port = 587
		d.Form.TLS = "starttls"
	}
	h.renderWith(w, "smtp.html", d)
}

func (h *Handler) smtpSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "csrf check failed", http.StatusForbidden)
		return
	}
	if r.FormValue("action") == "skip" {
		http.Redirect(w, r, "/setup/headscale", http.StatusSeeOther)
		return
	}
	port := 0
	_, _ = fmt.Sscanf(r.FormValue("port"), "%d", &port)
	cfg := settings.SMTP{
		Enabled:  true,
		Host:     strings.TrimSpace(r.FormValue("host")),
		Port:     port,
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
		From:     strings.TrimSpace(r.FormValue("from")),
		TLS:      r.FormValue("tls"),
	}
	if cfg.Host == "" {
		// Operator left it empty — treat like skip.
		cfg.Enabled = false
	}
	if err := settings.SaveSMTP(h.db, cfg); err != nil {
		h.renderWith(w, "smtp.html", smtpFormData{
			CSRF: h.ensureCSRF(w, r), Form: cfg, Error: "Save failed: " + err.Error(),
		})
		return
	}
	http.Redirect(w, r, "/setup/headscale", http.StatusSeeOther)
}

// ----- Step 3: Headscale connection -----

type hsFormData struct {
	Error string
	CSRF  string
	Form  settings.Headscale
}

func (h *Handler) headscaleForm(w http.ResponseWriter, r *http.Request) {
	d := hsFormData{CSRF: h.ensureCSRF(w, r)}
	d.Form, _ = settings.GetHeadscale(h.db)
	if d.Form.Address == "" {
		d.Form.Address = "http://127.0.0.1:8080"
	}
	h.renderWith(w, "headscale.html", d)
}

func (h *Handler) headscaleSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !h.checkCSRF(r) {
		http.Error(w, "csrf check failed", http.StatusForbidden)
		return
	}

	finishSetup := func() {
		if err := db.SetSetting(h.db, settingDone, "true"); err != nil {
			h.log.Error("mark setup complete", "err", err)
		}
		http.SetCookie(w, &http.Cookie{Name: cookieSetup, Value: "", Path: "/", MaxAge: -1})
		h.log.Info("setup complete")
		http.Redirect(w, r, "/setup/done", http.StatusSeeOther)
	}

	if r.FormValue("action") == "skip" {
		finishSetup()
		return
	}

	cfg := settings.Headscale{
		Enabled:   true,
		Address:   strings.TrimSpace(r.FormValue("address")),
		APIKey:    strings.TrimSpace(r.FormValue("api_key")),
		ClientURL: strings.TrimSpace(r.FormValue("client_url")),
		TLSSkip:   r.FormValue("tls_skip") == "on",
	}
	d := hsFormData{CSRF: h.ensureCSRF(w, r), Form: cfg}

	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	if err := headscale.TestConnection(ctx, cfg); err != nil {
		d.Error = "Connection failed: " + err.Error()
		h.renderWith(w, "headscale.html", d)
		return
	}
	if err := settings.SaveHeadscale(h.db, cfg); err != nil {
		d.Error = "Save failed: " + err.Error()
		h.renderWith(w, "headscale.html", d)
		return
	}
	finishSetup()
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
		Address string `json:"address"`
		APIKey  string `json:"api_key"`
		TLSSkip bool   `json:"tls_skip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "bad json"})
		return
	}
	cfg := settings.Headscale{
		Enabled: true,
		Address: req.Address,
		APIKey:  req.APIKey,
		TLSSkip: req.TLSSkip,
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
