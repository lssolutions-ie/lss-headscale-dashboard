package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/audit"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/headscale"
)

// ParsedPolicy is a best-effort decode of the Tailscale-style ACL policy JSON.
// We accept HuJSON (JSON-with-comments) by stripping comments before json.Unmarshal.
type ParsedPolicy struct {
	Groups    map[string][]string `json:"groups,omitempty"`
	TagOwners map[string][]string `json:"tagOwners,omitempty"`
	ACLs      []ACLRule           `json:"acls,omitempty"`
	SSH       []SSHRule           `json:"ssh,omitempty"`
	NodeAttrs []map[string]any    `json:"nodeAttrs,omitempty"`
	Hosts     map[string]string   `json:"hosts,omitempty"`
}

type ACLRule struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
	Proto  string   `json:"proto,omitempty"`
}

type SSHRule struct {
	Action  string   `json:"action"`
	Src     []string `json:"src"`
	Dst     []string `json:"dst"`
	Users   []string `json:"users,omitempty"`
	CheckPe string   `json:"checkPeriod,omitempty"`
}

// stripHuJSONComments removes `//` and `/* */` comments so encoding/json can parse it.
// Trailing commas are also tolerated by extending the cleanup.
var (
	reLineComment  = regexp.MustCompile(`(?m)//[^\n]*`)
	reBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reTrailComma   = regexp.MustCompile(`,(\s*[}\]])`)
)

func parsePolicy(raw string) *ParsedPolicy {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	cleaned := reBlockComment.ReplaceAllString(raw, "")
	cleaned = reLineComment.ReplaceAllString(cleaned, "")
	cleaned = reTrailComma.ReplaceAllString(cleaned, "$1")
	var p ParsedPolicy
	if err := json.Unmarshal([]byte(cleaned), &p); err != nil {
		return nil
	}
	return &p
}

// Routes exposed by policy.go:
//   GET  /policy
//   POST /policy                  (raw save)
//   POST /policy/rules/add        (append acls rule)
//   POST /policy/groups/add       (append/replace group)
//   POST /policy/tagowners/add    (append/replace tag owner)
func (h *Handler) RegisterPolicyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /policy", h.policyShow)
	mux.HandleFunc("POST /policy", h.policySaveRaw)
	mux.HandleFunc("POST /policy/rules/add", h.policyAddRule)
	mux.HandleFunc("POST /policy/groups/add", h.policyAddGroup)
	mux.HandleFunc("POST /policy/tagowners/add", h.policyAddTagOwner)
}

func (h *Handler) policyShow(w http.ResponseWriter, r *http.Request) {
	bp := h.loadBase(w, r, "policy")
	type pageData struct {
		basePage
		RawPolicy string
		UpdatedAt string
		Parsed    *ParsedPolicy
	}
	pd := pageData{basePage: bp}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		pd.HeadscaleError = errStr
		h.render(w, "policy.html", pd)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pol, err := c.GetPolicy(ctx)
	if err != nil {
		pd.HeadscaleError = "Could not load policy: " + err.Error()
	} else {
		pd.RawPolicy = pol.Policy
		pd.UpdatedAt = pol.UpdatedAt
		pd.Parsed = parsePolicy(pol.Policy)
	}
	h.render(w, "policy.html", pd)
}

func (h *Handler) policySaveRaw(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		setFlash(w, "danger", errStr)
		http.Redirect(w, r, "/policy", http.StatusSeeOther)
		return
	}
	body := r.FormValue("policy")
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	if err := c.SetPolicy(ctx, body); err != nil {
		setFlash(w, "danger", "Save failed: "+err.Error())
	} else {
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "policy", nil)
		setFlash(w, "success", "Policy saved.")
	}
	http.Redirect(w, r, "/policy", http.StatusSeeOther)
}

// loadAndMutate fetches the current policy, parses it (creating an empty one if absent),
// runs `mutate`, and writes the result back as canonical JSON.
func (h *Handler) loadAndMutate(ctx context.Context, c *headscale.Client, mutate func(*ParsedPolicy)) error {
	pol, err := c.GetPolicy(ctx)
	if err != nil {
		return err
	}
	parsed := parsePolicy(pol.Policy)
	if parsed == nil {
		parsed = &ParsedPolicy{}
	}
	mutate(parsed)
	out, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return err
	}
	return c.SetPolicy(ctx, string(out))
}

func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (h *Handler) policyAddRule(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		setFlash(w, "danger", errStr)
		http.Redirect(w, r, "/policy", http.StatusSeeOther)
		return
	}
	src := splitCSV(r.FormValue("src"))
	dst := splitCSV(r.FormValue("dst"))
	if len(src) == 0 || len(dst) == 0 {
		setFlash(w, "danger", "Both source(s) and destination(s) are required.")
		http.Redirect(w, r, "/policy", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	err := h.loadAndMutate(ctx, c, func(p *ParsedPolicy) {
		p.ACLs = append(p.ACLs, ACLRule{Action: "accept", Src: src, Dst: dst})
	})
	if err != nil {
		setFlash(w, "danger", "Add rule failed: "+err.Error())
	} else {
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "policy.rule", map[string]any{"src": src, "dst": dst})
		setFlash(w, "success", "Rule appended.")
	}
	http.Redirect(w, r, "/policy", http.StatusSeeOther)
}

func (h *Handler) policyAddGroup(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		setFlash(w, "danger", errStr)
		http.Redirect(w, r, "/policy", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if !strings.HasPrefix(name, "group:") {
		setFlash(w, "danger", "Group name must start with 'group:'.")
		http.Redirect(w, r, "/policy", http.StatusSeeOther)
		return
	}
	members := splitCSV(r.FormValue("members"))
	if len(members) == 0 {
		setFlash(w, "danger", "Members are required.")
		http.Redirect(w, r, "/policy", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	err := h.loadAndMutate(ctx, c, func(p *ParsedPolicy) {
		if p.Groups == nil {
			p.Groups = map[string][]string{}
		}
		p.Groups[name] = members
	})
	if err != nil {
		setFlash(w, "danger", "Save failed: "+err.Error())
	} else {
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "policy.group", map[string]any{"name": name})
		setFlash(w, "success", "Group saved.")
	}
	http.Redirect(w, r, "/policy", http.StatusSeeOther)
}

func (h *Handler) policyAddTagOwner(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		setFlash(w, "danger", errStr)
		http.Redirect(w, r, "/policy", http.StatusSeeOther)
		return
	}
	tag := strings.TrimSpace(r.FormValue("tag"))
	if !strings.HasPrefix(tag, "tag:") {
		setFlash(w, "danger", "Tag must start with 'tag:'.")
		http.Redirect(w, r, "/policy", http.StatusSeeOther)
		return
	}
	owners := splitCSV(r.FormValue("owners"))
	if len(owners) == 0 {
		setFlash(w, "danger", "Owners are required.")
		http.Redirect(w, r, "/policy", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	err := h.loadAndMutate(ctx, c, func(p *ParsedPolicy) {
		if p.TagOwners == nil {
			p.TagOwners = map[string][]string{}
		}
		p.TagOwners[tag] = owners
	})
	if err != nil {
		setFlash(w, "danger", "Save failed: "+err.Error())
	} else {
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "policy.tagowner", map[string]any{"tag": tag})
		setFlash(w, "success", "Tag owner saved.")
	}
	http.Redirect(w, r, "/policy", http.StatusSeeOther)
}
