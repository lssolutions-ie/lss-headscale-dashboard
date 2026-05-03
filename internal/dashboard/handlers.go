package dashboard

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/audit"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/auth"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/headscale"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/headscaledb"
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

var templateFuncs = template.FuncMap{
	"contains":  strings.Contains,
	"hasPrefix": strings.HasPrefix,
	"truncate": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "…"
	},
}

func New(d *sql.DB, log *slog.Logger) (*Handler, error) {
	t, err := template.New("dashboard").Funcs(templateFuncs).ParseFS(TemplateFS, TemplateGlob)
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
	mux.HandleFunc("POST /nodes/edit", h.nodesEdit)
	mux.HandleFunc("POST /nodes/register", h.nodesRegister)
	mux.HandleFunc("GET /preauthkeys", h.preAuthKeys)
	mux.HandleFunc("POST /preauthkeys/create", h.preAuthKeysCreate)
	mux.HandleFunc("POST /preauthkeys/expire", h.preAuthKeysExpire)
	mux.HandleFunc("GET /audit", h.auditPage)
	h.RegisterTagRoutes(mux)
	h.RegisterPolicyRoutes(mux)
	mux.HandleFunc("GET /settings", h.settings)
	mux.HandleFunc("POST /settings/headscale", h.settingsSaveHeadscale)
	mux.HandleFunc("POST /settings/headscale/test", h.settingsTestHeadscale)
	mux.HandleFunc("POST /settings/smtp", h.settingsSaveSMTP)
	mux.HandleFunc("POST /settings/smtp/test", h.settingsTestSMTP)
	mux.HandleFunc("POST /settings/headscale-db", h.settingsSaveHeadscaleDB)
	mux.HandleFunc("POST /settings/headscale-db/test", h.settingsTestHeadscaleDB)
	mux.HandleFunc("POST /settings/password", h.settingsPassword)
	mux.HandleFunc("POST /headscale/restart", h.headscaleRestart)
	mux.HandleFunc("GET /headscale/ready", h.headscaleReady)
	mux.HandleFunc("GET /nodes/wait", h.nodesWait)
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
		Nodes      []headscale.Node
		UsersList  []string // values present on existing nodes (incl. virtual 'tagged-devices') — for the table filter
		RealUsers  []string // actual Headscale users from ListUsers — for Register Node dropdown
		TagsList   []string
		DBEnabled  bool
		DBNodes    map[string]headscaledb.FullNode
		DBColumns  []string
		ClientURL  string
		KnownTags  []string
	}
	pd := pageData{basePage: bp}
	hdb, _ := settings.GetHeadscaleDB(h.db)
	if hdb.Enabled && hdb.Path != "" {
		pd.DBEnabled = true
		if full, err := headscaledb.New(hdb).ListFullNodes(); err == nil {
			pd.DBNodes = full
		}
		pd.DBColumns = headscaledb.AllowedColumns
	}
	if hs, _ := settings.GetHeadscale(h.db); hs.ClientURL != "" {
		pd.ClientURL = hs.ClientURL
	} else if hs.Address != "" {
		pd.ClientURL = hs.Address
	}
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
			pd.TagsList = uniqueTagsFromNodes(ns)
		}
		// Real Headscale users (for the Register Node "Owner user" dropdown).
		// `tagged-devices` is a virtual user Headscale auto-assigns to tagged
		// nodes — it isn't a real user and can't own a pre-auth key.
		if realUsers, err := c.ListUsers(ctx); err == nil {
			for _, u := range realUsers {
				if u.Name != "" {
					pd.RealUsers = append(pd.RealUsers, u.Name)
				}
			}
			sort.Strings(pd.RealUsers)
		}
		// Tags defined as keys of tagOwners in the ACL policy.
		if pol, err := c.GetPolicy(ctx); err == nil {
			if parsed := parsePolicy(pol.Policy); parsed != nil {
				for tag := range parsed.TagOwners {
					pd.KnownTags = append(pd.KnownTags, tag)
				}
				sort.Strings(pd.KnownTags)
			}
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

// nodesRegister creates a pre-auth key for a new node and returns a JSON
// payload with a ready-to-paste `tailscale up` command.
func (h *Handler) nodesRegister(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "csrf check failed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad form"})
		return
	}
	user := strings.TrimSpace(r.FormValue("user"))
	hostname := strings.TrimSpace(r.FormValue("hostname"))
	tags := splitCSV(r.FormValue("tags"))
	reusable := r.FormValue("reusable") == "on"
	ephemeral := r.FormValue("ephemeral") == "on"
	exp := strings.TrimSpace(r.FormValue("expiration"))
	loginServer := strings.TrimSpace(r.FormValue("login_server"))

	if user == "" || loginServer == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "user and login_server are required"})
		return
	}
	for _, t := range tags {
		if !strings.HasPrefix(t, "tag:") {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "each tag must start with 'tag:' (got: " + t + ")"})
			return
		}
	}

	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": errStr})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	key, err := c.CreatePreAuthKey(ctx, user, reusable, ephemeral, tags, exp)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	cmd := buildRegisterCommand(registerOpts{
		LoginServer:       loginServer,
		Key:               key.Key,
		Hostname:          hostname,
		Tags:              tags,
		AcceptDNS:         strings.TrimSpace(r.FormValue("accept_dns")),
		AcceptRoutes:      strings.TrimSpace(r.FormValue("accept_routes")),
		AdvertiseExitNode: r.FormValue("advertise_exit_node") == "on",
		AdvertiseRoutes:   strings.TrimSpace(r.FormValue("advertise_routes")),
		ExitNode:          strings.TrimSpace(r.FormValue("exit_node")),
		ExitNodeLAN:       r.FormValue("exit_node_lan") == "on",
		Reset:             r.FormValue("reset") == "on",
		ForceReauth:       r.FormValue("force_reauth") == "on",
		Unattended:        r.FormValue("unattended") == "on",
		ShieldsUp:         r.FormValue("shields_up") == "on",
		SSH:               r.FormValue("ssh") == "on",
		Operator:          strings.TrimSpace(r.FormValue("operator")),
		Timeout:           strings.TrimSpace(r.FormValue("timeout")),
		Nickname:          strings.TrimSpace(r.FormValue("nickname")),
		NetfilterMode:     strings.TrimSpace(r.FormValue("netfilter_mode")),
		SNATSubnetRoutes:  strings.TrimSpace(r.FormValue("snat_subnet_routes")),
		StatefulFiltering: strings.TrimSpace(r.FormValue("stateful_filtering")),
		AcceptRisk:        strings.TrimSpace(r.FormValue("accept_risk")),
	})
	audit.Write(h.db, actorID(r), currentIP(r), audit.ActionPreAuthKeyCreate, user, map[string]any{
		"reusable": reusable, "ephemeral": ephemeral, "tags": tags, "via": "register-node",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "command": cmd, "key": key.Key})
}

type registerOpts struct {
	LoginServer        string
	Key                string
	Hostname           string
	Nickname           string
	Tags               []string
	AcceptDNS          string // "" | "true" | "false"
	AcceptRoutes       string
	AdvertiseExitNode  bool
	AdvertiseRoutes    string
	ExitNode           string
	ExitNodeLAN        bool
	Reset              bool
	ForceReauth        bool
	Unattended         bool
	ShieldsUp          bool
	SSH                bool
	Operator           string
	Timeout            string
	NetfilterMode      string // "" | "on" | "off" | "nodivert"
	SNATSubnetRoutes   string // "" | "true" | "false"
	StatefulFiltering  string // "" | "true" | "false"
	AcceptRisk         string // e.g. "lose-ssh" or "all"
}

func buildRegisterCommand(o registerOpts) string {
	parts := []string{
		"sudo tailscale up",
		"  --login-server=" + o.LoginServer,
		"  --authkey=" + o.Key,
	}
	if o.Hostname != "" {
		parts = append(parts, "  --hostname="+shellArg(o.Hostname))
	}
	if o.Nickname != "" {
		parts = append(parts, "  --nickname="+shellArg(o.Nickname))
	}
	if len(o.Tags) > 0 {
		parts = append(parts, "  --advertise-tags="+strings.Join(o.Tags, ","))
	}
	if o.AcceptDNS != "" {
		parts = append(parts, "  --accept-dns="+o.AcceptDNS)
	}
	if o.AcceptRoutes != "" {
		parts = append(parts, "  --accept-routes="+o.AcceptRoutes)
	}
	if o.AdvertiseExitNode {
		parts = append(parts, "  --advertise-exit-node")
	}
	if o.AdvertiseRoutes != "" {
		parts = append(parts, "  --advertise-routes="+o.AdvertiseRoutes)
	}
	if o.ExitNode != "" {
		parts = append(parts, "  --exit-node="+shellArg(o.ExitNode))
	}
	if o.ExitNodeLAN {
		parts = append(parts, "  --exit-node-allow-lan-access")
	}
	if o.Reset {
		parts = append(parts, "  --reset")
	}
	if o.ForceReauth {
		parts = append(parts, "  --force-reauth")
	}
	if o.Unattended {
		parts = append(parts, "  --unattended")
	}
	if o.ShieldsUp {
		parts = append(parts, "  --shields-up")
	}
	if o.SSH {
		parts = append(parts, "  --ssh")
	}
	if o.Operator != "" {
		parts = append(parts, "  --operator="+shellArg(o.Operator))
	}
	if o.Timeout != "" {
		parts = append(parts, "  --timeout="+o.Timeout)
	}
	if o.NetfilterMode != "" {
		parts = append(parts, "  --netfilter-mode="+o.NetfilterMode)
	}
	if o.SNATSubnetRoutes != "" {
		parts = append(parts, "  --snat-subnet-routes="+o.SNATSubnetRoutes)
	}
	if o.StatefulFiltering != "" {
		parts = append(parts, "  --stateful-filtering="+o.StatefulFiltering)
	}
	if o.AcceptRisk != "" {
		parts = append(parts, "  --accept-risk="+o.AcceptRisk)
	}
	return strings.Join(parts, " \\\n")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func shellArg(s string) string {
	if !strings.ContainsAny(s, " '\"$`\\") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// nodesEdit handles the unified Edit Node form: API-managed fields
// (given_name, tags, owner user) and DB-managed fields (ipv4/ipv6/hostname).
func (h *Handler) nodesEdit(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	var changes []string
	var firstErr error
	var restarted bool

	// DB: every whitelisted column. Values come straight from the form;
	// we diff against the current DB row so only changed columns are written.
	hdbCfg, _ := settings.GetHeadscaleDB(h.db)
	if hdbCfg.Enabled && hdbCfg.Path != "" {
		hdbClient := headscaledb.New(hdbCfg)
		dbNodes, err := hdbClient.ListFullNodes()
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("db read: %w", err)
			}
		}
		currentRow := dbNodes[id]
		dbFields := map[string]string{}
		for _, col := range headscaledb.AllowedColumns {
			formName := col
			if col == "id" {
				formName = "new_id" // routing field is `id`; new value lives in `new_id`
			}
			submitted := r.FormValue(formName)
			// If the form didn't carry this column at all, leave it alone.
			if _, present := r.PostForm[formName]; !present {
				continue
			}
			if submitted == currentRow[col] {
				continue
			}
			if col == "id" {
				if n, err := strconv.Atoi(submitted); err != nil || n <= 0 {
					setFlash(w, "danger", "New ID must be a positive integer.")
					http.Redirect(w, r, "/nodes", http.StatusSeeOther)
					return
				}
			}
			dbFields[col] = submitted
		}
		if len(dbFields) > 0 {
			n, err := hdbClient.UpdateNodeFields(id, dbFields)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("db update: %w", err)
				}
			} else {
				cols := make([]string, 0, len(dbFields))
				for k := range dbFields {
					cols = append(cols, k)
				}
				changes = append(changes, fmt.Sprintf("db: %s (rows=%d)", strings.Join(cols, ","), n))
				if r.FormValue("restart_after") == "on" {
					out, err := hdbClient.RestartHeadscale()
					if err != nil {
						changes = append(changes, "restart FAILED: "+err.Error()+" "+strings.TrimSpace(out))
					} else {
						changes = append(changes, "headscale restarted")
						restarted = true
					}
				}
			}
		}
	}

	if len(changes) > 0 {
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "node."+id, map[string]any{"changes": changes})
	}
	if firstErr != nil {
		setFlash(w, "danger", "Some changes failed: "+firstErr.Error()+". Applied: "+strings.Join(changes, "; "))
	} else if len(changes) == 0 {
		setFlash(w, "info", "No changes.")
	} else {
		setFlash(w, "success", "Saved: "+strings.Join(changes, "; "))
	}
	if restarted {
		http.Redirect(w, r, "/nodes/wait?to=/nodes", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/nodes", http.StatusSeeOther)
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	am := map[string]bool{}
	for _, s := range a {
		am[s] = true
	}
	for _, s := range b {
		if !am[s] {
			return false
		}
	}
	return true
}

// settingsSaveHeadscaleDB persists the local-DB editing config.
func (h *Handler) settingsSaveHeadscaleDB(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	cfg := settings.HeadscaleDB{
		Enabled:    r.FormValue("enabled") == "on",
		Path:       strings.TrimSpace(r.FormValue("path")),
		RestartCmd: strings.TrimSpace(r.FormValue("restart_cmd")),
	}
	if cfg.Path == "" {
		cfg.Path = headscaledb.DefaultPath
	}
	if cfg.RestartCmd == "" {
		cfg.RestartCmd = headscaledb.DefaultRestartCmd
	}
	if err := settings.SaveHeadscaleDB(h.db, cfg); err != nil {
		setFlash(w, "danger", "Save failed: "+err.Error())
	} else {
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "headscale_db", nil)
		setFlash(w, "success", "Headscale DB settings saved.")
	}
	http.Redirect(w, r, "/settings#headscale-db", http.StatusSeeOther)
}

func (h *Handler) settingsTestHeadscaleDB(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	cfg := settings.HeadscaleDB{
		Enabled:    true,
		Path:       strings.TrimSpace(r.FormValue("path")),
		RestartCmd: strings.TrimSpace(r.FormValue("restart_cmd")),
	}
	if cfg.Path == "" {
		cfg.Path = headscaledb.DefaultPath
	}
	if err := headscaledb.New(cfg).Test(); err != nil {
		setFlash(w, "danger", "DB test failed: "+err.Error())
	} else {
		_ = settings.SaveHeadscaleDB(h.db, cfg)
		setFlash(w, "success", "Read OK from "+cfg.Path+". Settings saved.")
	}
	http.Redirect(w, r, "/settings#headscale-db", http.StatusSeeOther)
}

// headscaleReady returns {"ready": true} if Headscale's API responds.
// Used by the wait/spinner page to know when to redirect.
func (h *Handler) headscaleReady(w http.ResponseWriter, r *http.Request) {
	c, _ := h.headscaleClient(r.Context())
	w.Header().Set("Content-Type", "application/json")
	if c == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": false})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ready": true})
}

// nodesWait renders a spinner page that polls /headscale/ready, then
// redirects to ?to=/path when Headscale answers.
func (h *Handler) nodesWait(w http.ResponseWriter, r *http.Request) {
	bp := h.loadBase(w, r, "nodes")
	type pageData struct {
		basePage
		Address  string
		Redirect string
	}
	pd := pageData{basePage: bp, Redirect: "/nodes"}
	if to := r.URL.Query().Get("to"); to != "" && strings.HasPrefix(to, "/") {
		pd.Redirect = to
	}
	if hs, _ := settings.GetHeadscale(h.db); hs.Address != "" {
		pd.Address = hs.Address
	}
	h.render(w, "wait.html", pd)
}

func (h *Handler) headscaleRestart(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	cfg, _ := settings.GetHeadscaleDB(h.db)
	if !cfg.Enabled {
		setFlash(w, "warning", "Local DB editing not enabled.")
		http.Redirect(w, r, "/settings#headscale-db", http.StatusSeeOther)
		return
	}
	out, err := headscaledb.New(cfg).RestartHeadscale()
	if err != nil {
		setFlash(w, "danger", "Restart failed: "+err.Error()+" "+strings.TrimSpace(out))
		http.Redirect(w, r, "/settings#headscale-db", http.StatusSeeOther)
		return
	}
	audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "headscale.restart", nil)
	setFlash(w, "success", "Headscale restarted.")
	http.Redirect(w, r, "/nodes/wait?to=/settings", http.StatusSeeOther)
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

func uniqueTagsFromNodes(nodes []headscale.Node) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range nodes {
		for _, t := range n.Tags {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
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
		DBEnabled bool
	}
	pd := pageData{basePage: bp}
	if hdb, _ := settings.GetHeadscaleDB(h.db); hdb.Enabled && hdb.Path != "" {
		pd.DBEnabled = true
	}
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
		Headscale   settings.Headscale
		HeadscaleDB settings.HeadscaleDB
		SMTP        settings.SMTP
		Passkeys    []passkeyView
	}
	pd := pageData{basePage: bp}
	pd.Headscale, _ = settings.GetHeadscale(h.db)
	pd.HeadscaleDB, _ = settings.GetHeadscaleDB(h.db)
	if pd.HeadscaleDB.Path == "" {
		pd.HeadscaleDB.Path = headscaledb.DefaultPath
	}
	if pd.HeadscaleDB.RestartCmd == "" {
		pd.HeadscaleDB.RestartCmd = headscaledb.DefaultRestartCmd
	}
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
		Enabled:   true,
		Address:   strings.TrimSpace(r.FormValue("address")),
		APIKey:    strings.TrimSpace(r.FormValue("api_key")),
		TLSSkip:   r.FormValue("tls_skip") == "on",
		ClientURL: strings.TrimSpace(r.FormValue("client_url")),
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
		Enabled:   true,
		Address:   strings.TrimSpace(r.FormValue("address")),
		APIKey:    strings.TrimSpace(r.FormValue("api_key")),
		TLSSkip:   r.FormValue("tls_skip") == "on",
		ClientURL: strings.TrimSpace(r.FormValue("client_url")),
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
