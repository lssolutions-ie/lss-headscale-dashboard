package dashboard

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/audit"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/auth"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/headscale"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/settings"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/smtp"
)

//go:embed templates/*.html
var TemplateFS embed.FS

const TemplateGlob = "templates/*.html"

const cookieFlash = "lss_flash"

type Handler struct {
	db   *sql.DB
	log  *slog.Logger
	tmpl *template.Template
}

func New(d *sql.DB, log *slog.Logger) (*Handler, error) {
	t, err := template.ParseFS(TemplateFS, TemplateGlob)
	if err != nil {
		return nil, err
	}
	return &Handler{db: d, log: log, tmpl: t}, nil
}

type viewUser struct {
	ID       int64
	Username string
	Initial  string
}

type flash struct {
	Kind    string // success | warning | danger | info
	Message string
}

type basePage struct {
	Active         string
	User           *viewUser
	CSRF           string
	Flash          *flash
	HeadscaleError string
}

// Routes registers all authenticated dashboard routes. The caller wraps these
// with auth middleware.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", h.home)
	mux.HandleFunc("GET /users", h.users)
	mux.HandleFunc("POST /users/create", h.usersCreate)
	mux.HandleFunc("POST /users/delete", h.usersDelete)
	mux.HandleFunc("GET /nodes", h.nodes)
	mux.HandleFunc("POST /nodes/expire", h.nodesExpire)
	mux.HandleFunc("POST /nodes/delete", h.nodesDelete)
	mux.HandleFunc("POST /nodes/tags", h.nodesTags)
	mux.HandleFunc("GET /preauthkeys", h.preAuthKeys)
	mux.HandleFunc("POST /preauthkeys/create", h.preAuthKeysCreate)
	mux.HandleFunc("POST /preauthkeys/expire", h.preAuthKeysExpire)
	mux.HandleFunc("GET /audit", h.auditPage)
	h.RegisterPolicyRoutes(mux)
	mux.HandleFunc("GET /settings", h.settings)
	mux.HandleFunc("POST /settings/headscale", h.settingsSaveHeadscale)
	mux.HandleFunc("POST /settings/headscale/test", h.settingsTestHeadscale)
	mux.HandleFunc("POST /settings/smtp", h.settingsSaveSMTP)
	mux.HandleFunc("POST /settings/smtp/test", h.settingsTestSMTP)
	mux.HandleFunc("POST /settings/password", h.settingsPassword)
}

// ----- Helpers -----

func (h *Handler) loadBase(w http.ResponseWriter, r *http.Request, active string) basePage {
	s := auth.SessionFrom(r.Context())
	bp := basePage{Active: active}
	if s != nil {
		var u viewUser
		err := h.db.QueryRow(`SELECT id, username FROM users WHERE id = ?`, s.UserID).Scan(&u.ID, &u.Username)
		if err == nil {
			if len(u.Username) > 0 {
				u.Initial = strings.ToUpper(u.Username[:1])
			}
			bp.User = &u
		}
	}
	bp.CSRF = h.ensureCSRF(w, r)
	bp.Flash = readFlash(w, r)
	return bp
}

func (h *Handler) ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("lss_csrf"); err == nil && len(c.Value) >= 24 {
		return c.Value
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name: "lss_csrf", Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 3600,
	})
	return tok
}

func (h *Handler) checkCSRF(r *http.Request) bool {
	c, err := r.Cookie("lss_csrf")
	if err != nil {
		return false
	}
	return r.FormValue("csrf") != "" && r.FormValue("csrf") == c.Value
}

func (h *Handler) render(w http.ResponseWriter, body string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, err := h.tmpl.Clone()
	if err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	if _, err := t.ParseFS(TemplateFS, "templates/"+body); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		h.log.Error("render", "body", body, "err", err)
	}
}

func setFlash(w http.ResponseWriter, kind, msg string) {
	v := kind + "|" + msg
	http.SetCookie(w, &http.Cookie{
		Name: cookieFlash, Value: base64.RawURLEncoding.EncodeToString([]byte(v)),
		Path: "/", MaxAge: 60, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func readFlash(w http.ResponseWriter, r *http.Request) *flash {
	c, err := r.Cookie(cookieFlash)
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: cookieFlash, Value: "", Path: "/", MaxAge: -1})
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	parts := strings.SplitN(string(b), "|", 2)
	if len(parts) != 2 {
		return nil
	}
	return &flash{Kind: parts[0], Message: parts[1]}
}

func (h *Handler) headscaleClient(ctx context.Context) (*headscale.Client, string) {
	cfg, err := settings.GetHeadscale(h.db)
	if err != nil {
		return nil, "Could not load Headscale settings."
	}
	if !cfg.Enabled || cfg.Address == "" || cfg.APIKey == "" {
		return nil, "Headscale is not configured yet."
	}
	c := headscale.New(cfg)
	dctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := c.Ping(dctx); err != nil {
		return nil, "Cannot reach Headscale: " + err.Error()
	}
	return c, ""
}

func currentIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		if i := strings.Index(x, ","); i >= 0 {
			return strings.TrimSpace(x[:i])
		}
		return x
	}
	return r.RemoteAddr
}

// ----- Pages -----

func (h *Handler) home(w http.ResponseWriter, r *http.Request) {
	bp := h.loadBase(w, r, "home")
	type stats struct{ Users, Nodes, Online, Keys int }
	type pageData struct {
		basePage
		Stats  stats
		Recent []audit.Entry
	}
	pd := pageData{basePage: bp}
	pd.Recent, _ = audit.List(h.db, 15, 0)

	if c, errStr := h.headscaleClient(r.Context()); c != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		if users, err := c.ListUsers(ctx); err == nil {
			pd.Stats.Users = len(users)
		}
		if nodes, err := c.ListNodes(ctx, ""); err == nil {
			pd.Stats.Nodes = len(nodes)
			for _, n := range nodes {
				if n.Online {
					pd.Stats.Online++
				}
			}
		}
		if keys, err := c.ListPreAuthKeys(ctx, ""); err == nil {
			pd.Stats.Keys = len(keys)
		}
	} else {
		pd.HeadscaleError = errStr
	}
	h.render(w, "home.html", pd)
}

func (h *Handler) users(w http.ResponseWriter, r *http.Request) {
	bp := h.loadBase(w, r, "users")
	type pageData struct {
		basePage
		Users []headscale.User
	}
	pd := pageData{basePage: bp}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		pd.HeadscaleError = errStr
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		us, err := c.ListUsers(ctx)
		if err != nil {
			pd.HeadscaleError = err.Error()
		} else {
			pd.Users = us
		}
	}
	h.render(w, "users.html", pd)
}

func (h *Handler) usersCreate(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		setFlash(w, "danger", errStr)
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	email := strings.TrimSpace(r.FormValue("email"))
	if name == "" {
		setFlash(w, "danger", "Name is required.")
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	if _, err := c.CreateUser(ctx, name, email); err != nil {
		setFlash(w, "danger", "Create failed: "+err.Error())
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	uid := actorID(r)
	audit.Write(h.db, uid, currentIP(r), audit.ActionUserCreate, name, map[string]any{"email": email})
	setFlash(w, "success", "User created.")
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (h *Handler) usersDelete(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		setFlash(w, "danger", errStr)
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	name := r.FormValue("name")
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	if err := c.DeleteUser(ctx, name); err != nil {
		setFlash(w, "danger", "Delete failed: "+err.Error())
	} else {
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionUserDelete, name, nil)
		setFlash(w, "success", "User deleted.")
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (h *Handler) nodes(w http.ResponseWriter, r *http.Request) {
	bp := h.loadBase(w, r, "nodes")
	type pageData struct {
		basePage
		Nodes     []headscale.Node
		UsersList []string
	}
	pd := pageData{basePage: bp}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		pd.HeadscaleError = errStr
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		ns, err := c.ListNodes(ctx, "")
		if err != nil {
			pd.HeadscaleError = err.Error()
		} else {
			pd.Nodes = ns
			pd.UsersList = uniqueUsersFromNodes(ns)
		}
	}
	h.render(w, "nodes.html", pd)
}

func (h *Handler) nodesTags(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		setFlash(w, "danger", errStr)
		http.Redirect(w, r, "/nodes", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	tags := splitCSV(r.FormValue("tags"))
	for _, t := range tags {
		if !strings.HasPrefix(t, "tag:") {
			setFlash(w, "danger", "Each tag must start with 'tag:'. Got: "+t)
			http.Redirect(w, r, "/nodes", http.StatusSeeOther)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	if err := c.SetNodeTags(ctx, id, tags); err != nil {
		setFlash(w, "danger", "Set tags failed: "+err.Error())
	} else {
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "node.tags."+id, map[string]any{"tags": tags})
		setFlash(w, "success", "Tags updated.")
	}
	http.Redirect(w, r, "/nodes", http.StatusSeeOther)
}

func uniqueUsersFromNodes(nodes []headscale.Node) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range nodes {
		if n.User.Name != "" && !seen[n.User.Name] {
			seen[n.User.Name] = true
			out = append(out, n.User.Name)
		}
	}
	return out
}

func (h *Handler) nodesExpire(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		setFlash(w, "danger", errStr)
		http.Redirect(w, r, "/nodes", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	if err := c.ExpireNode(ctx, id); err != nil {
		setFlash(w, "danger", "Expire failed: "+err.Error())
	} else {
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionNodeExpire, id, nil)
		setFlash(w, "success", "Node expired.")
	}
	http.Redirect(w, r, "/nodes", http.StatusSeeOther)
}

func (h *Handler) nodesDelete(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		setFlash(w, "danger", errStr)
		http.Redirect(w, r, "/nodes", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	if err := c.DeleteNode(ctx, id); err != nil {
		setFlash(w, "danger", "Delete failed: "+err.Error())
	} else {
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionNodeDelete, id, nil)
		setFlash(w, "success", "Node deleted.")
	}
	http.Redirect(w, r, "/nodes", http.StatusSeeOther)
}

func (h *Handler) preAuthKeys(w http.ResponseWriter, r *http.Request) {
	bp := h.loadBase(w, r, "preauthkeys")
	type pageData struct {
		basePage
		Keys      []headscale.PreAuthKey
		Users     []headscale.User
		UsersList []string
		NewKey    string
	}
	pd := pageData{basePage: bp}
	if v := r.URL.Query().Get("new"); v != "" {
		pd.NewKey = v
	}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		pd.HeadscaleError = errStr
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		pd.Keys, _ = c.ListPreAuthKeys(ctx, "")
		pd.Users, _ = c.ListUsers(ctx)
		for _, u := range pd.Users {
			pd.UsersList = append(pd.UsersList, u.Name)
		}
	}
	h.render(w, "preauthkeys.html", pd)
}

func (h *Handler) preAuthKeysCreate(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		setFlash(w, "danger", errStr)
		http.Redirect(w, r, "/preauthkeys", http.StatusSeeOther)
		return
	}
	user := r.FormValue("user")
	reusable := r.FormValue("reusable") == "on"
	ephemeral := r.FormValue("ephemeral") == "on"
	exp := strings.TrimSpace(r.FormValue("expiration"))
	tags := splitCSV(r.FormValue("acl_tags"))
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	k, err := c.CreatePreAuthKey(ctx, user, reusable, ephemeral, tags, exp)
	if err != nil {
		setFlash(w, "danger", "Create failed: "+err.Error())
		http.Redirect(w, r, "/preauthkeys", http.StatusSeeOther)
		return
	}
	audit.Write(h.db, actorID(r), currentIP(r), audit.ActionPreAuthKeyCreate, user, map[string]any{"reusable": reusable, "ephemeral": ephemeral})
	http.Redirect(w, r, "/preauthkeys?new="+k.Key, http.StatusSeeOther)
}

func (h *Handler) preAuthKeysExpire(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		setFlash(w, "danger", errStr)
		http.Redirect(w, r, "/preauthkeys", http.StatusSeeOther)
		return
	}
	user := r.FormValue("user")
	key := r.FormValue("key")
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	if err := c.ExpirePreAuthKey(ctx, user, key); err != nil {
		setFlash(w, "danger", "Expire failed: "+err.Error())
	} else {
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionPreAuthKeyExpire, user, nil)
		setFlash(w, "success", "Pre-auth key expired.")
	}
	http.Redirect(w, r, "/preauthkeys", http.StatusSeeOther)
}

func (h *Handler) auditPage(w http.ResponseWriter, r *http.Request) {
	bp := h.loadBase(w, r, "audit")
	type pageData struct {
		basePage
		Entries []audit.Entry
	}
	pd := pageData{basePage: bp}
	pd.Entries, _ = audit.List(h.db, 200, 0)
	h.render(w, "audit.html", pd)
}

// ----- Settings -----

type passkeyView struct {
	ID        int64
	Label     string
	CreatedAt string
}

func (h *Handler) settings(w http.ResponseWriter, r *http.Request) {
	bp := h.loadBase(w, r, "settings")
	type pageData struct {
		basePage
		Headscale settings.Headscale
		SMTP      settings.SMTP
		Passkeys  []passkeyView
	}
	pd := pageData{basePage: bp}
	pd.Headscale, _ = settings.GetHeadscale(h.db)
	pd.SMTP, _ = settings.GetSMTP(h.db)
	if pd.SMTP.Port == 0 {
		pd.SMTP.Port = 587
		pd.SMTP.TLS = "starttls"
	}
	if bp.User != nil {
		rows, err := h.db.Query(`
			SELECT id, COALESCE(label,''), created_at FROM webauthn_credentials
			WHERE user_id = ? ORDER BY id DESC
		`, bp.User.ID)
		if err == nil {
			for rows.Next() {
				var pv passkeyView
				_ = rows.Scan(&pv.ID, &pv.Label, &pv.CreatedAt)
				pd.Passkeys = append(pd.Passkeys, pv)
			}
			rows.Close()
		}
	}
	h.render(w, "settings.html", pd)
}

func (h *Handler) settingsSaveHeadscale(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	cfg := settings.Headscale{
		Enabled: true,
		Address: strings.TrimSpace(r.FormValue("address")),
		APIKey:  strings.TrimSpace(r.FormValue("api_key")),
		TLSSkip: r.FormValue("tls_skip") == "on",
	}
	if err := settings.SaveHeadscale(h.db, cfg); err != nil {
		setFlash(w, "danger", "Save failed: "+err.Error())
	} else {
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "headscale", nil)
		setFlash(w, "success", "Headscale settings saved.")
	}
	http.Redirect(w, r, "/settings#headscale", http.StatusSeeOther)
}

func (h *Handler) settingsTestHeadscale(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	cfg := settings.Headscale{
		Enabled: true,
		Address: strings.TrimSpace(r.FormValue("address")),
		APIKey:  strings.TrimSpace(r.FormValue("api_key")),
		TLSSkip: r.FormValue("tls_skip") == "on",
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	if err := headscale.TestConnection(ctx, cfg); err != nil {
		setFlash(w, "danger", "Connection failed: "+err.Error())
	} else {
		_ = settings.SaveHeadscale(h.db, cfg)
		setFlash(w, "success", "Connected to Headscale. Settings saved.")
	}
	http.Redirect(w, r, "/settings#headscale", http.StatusSeeOther)
}

func (h *Handler) settingsSaveSMTP(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	port, _ := strconv.Atoi(r.FormValue("port"))
	cfg := settings.SMTP{
		Enabled:  r.FormValue("enabled") == "on",
		Host:     strings.TrimSpace(r.FormValue("host")),
		Port:     port,
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
		From:     strings.TrimSpace(r.FormValue("from")),
		TLS:      r.FormValue("tls"),
	}
	if err := settings.SaveSMTP(h.db, cfg); err != nil {
		setFlash(w, "danger", "Save failed: "+err.Error())
	} else {
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "smtp", nil)
		setFlash(w, "success", "SMTP settings saved.")
	}
	http.Redirect(w, r, "/settings#smtp", http.StatusSeeOther)
}

func (h *Handler) settingsTestSMTP(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	port, _ := strconv.Atoi(r.FormValue("port"))
	cfg := settings.SMTP{
		Enabled:  true,
		Host:     strings.TrimSpace(r.FormValue("host")),
		Port:     port,
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
		From:     strings.TrimSpace(r.FormValue("from")),
		TLS:      r.FormValue("tls"),
	}
	to := strings.TrimSpace(r.FormValue("test_to"))
	if to == "" {
		setFlash(w, "warning", "Provide a test recipient address.")
		http.Redirect(w, r, "/settings#smtp", http.StatusSeeOther)
		return
	}
	mailer := smtp.New(cfg)
	if err := mailer.Send(to, "LSS Headscale Dashboard SMTP test", "If you received this, your SMTP settings work."); err != nil {
		setFlash(w, "danger", "Test failed: "+err.Error())
	} else {
		_ = settings.SaveSMTP(h.db, cfg)
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSMTPTest, to, nil)
		setFlash(w, "success", "Test email sent. Settings saved.")
	}
	http.Redirect(w, r, "/settings#smtp", http.StatusSeeOther)
}

func (h *Handler) settingsPassword(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	s := auth.SessionFrom(r.Context())
	if s == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	cur := r.FormValue("current")
	newPw := r.FormValue("new")
	conf := r.FormValue("confirm")
	if newPw != conf {
		setFlash(w, "danger", "New passwords do not match.")
		http.Redirect(w, r, "/settings#password", http.StatusSeeOther)
		return
	}
	if len(newPw) < 12 {
		setFlash(w, "danger", "Password must be at least 12 characters.")
		http.Redirect(w, r, "/settings#password", http.StatusSeeOther)
		return
	}
	var hash string
	if err := h.db.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, s.UserID).Scan(&hash); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ok, err := auth.VerifyPassword(cur, hash)
	if err != nil || !ok {
		setFlash(w, "danger", "Current password is wrong.")
		http.Redirect(w, r, "/settings#password", http.StatusSeeOther)
		return
	}
	newHash, err := auth.HashPassword(newPw)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if _, err := h.db.Exec(`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, newHash, s.UserID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	audit.Write(h.db, actorID(r), currentIP(r), audit.ActionPasswordChange, "", nil)
	setFlash(w, "success", "Password changed.")
	http.Redirect(w, r, "/settings#password", http.StatusSeeOther)
}

// actorID returns a *int64 of the logged-in user's id, or nil if no session.
func actorID(r *http.Request) *int64 {
	s := auth.SessionFrom(r.Context())
	if s == nil {
		return nil
	}
	id := s.UserID
	return &id
}

// (compile-time guarantee): keep referenced symbols alive even if the package
// shape changes during builds.
var _ = errors.New
