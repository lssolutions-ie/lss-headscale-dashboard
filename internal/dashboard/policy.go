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

type policyPageData struct {
	basePage
	RawPolicy string
	UpdatedAt string
	Parsed    *ParsedPolicy
	ActiveTab string
	Actors    []string
	Members   []string
	Tags      []string
	Groups    []string
}

func (h *Handler) policyShow(w http.ResponseWriter, r *http.Request) {
	bp := h.loadBase(w, r, "policy")
	pd := policyPageData{basePage: bp}
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
	users, _ := c.ListUsers(ctx)
	pd.Actors, pd.Members, pd.Tags, pd.Groups = buildPolicyChoices(pd.Parsed, users)
	h.render(w, "policy.html", pd)
}

// buildPolicyChoices returns sorted chip-selectable values for the builder.
//   actors: groups + tags + hosts + users + "*"  (valid in src/dst)
//   members: users + groups                       (valid in group members / tagOwners owners)
//   tags: existing tag:* keys from tagOwners
//   groups: existing group:* keys
func buildPolicyChoices(p *ParsedPolicy, users []headscale.User) (actors, members, tags, groups []string) {
	actors = []string{"*"}
	if p != nil {
		for g := range p.Groups {
			groups = append(groups, g)
			actors = append(actors, g)
			members = append(members, g)
		}
		for t := range p.TagOwners {
			tags = append(tags, t)
			actors = append(actors, t)
		}
		for h := range p.Hosts {
			actors = append(actors, h)
		}
	}
	for _, u := range users {
		if u.Name == "" {
			continue
		}
		actors = append(actors, u.Name)
		members = append(members, u.Name)
	}
	sortStrings(&actors)
	sortStrings(&members)
	sortStrings(&tags)
	sortStrings(&groups)
	return
}

// splitHostPort splits an ACL `dst` entry like `tag:server:22,80` into
// ("tag:server", "22,80"). Returns the whole string as host with empty
// port if no separator found.
func splitHostPort(s string) (host, port string) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

// renameTagInPolicy walks every reference to oldTag and rewrites it to newTag:
// tagOwners map key, ACL src/dst, SSH src/dst.
func renameTagInPolicy(p *ParsedPolicy, oldTag, newTag string) {
	if p == nil || oldTag == newTag {
		return
	}
	if p.TagOwners != nil {
		if owners, ok := p.TagOwners[oldTag]; ok {
			p.TagOwners[newTag] = owners
			delete(p.TagOwners, oldTag)
		}
	}
	for i := range p.ACLs {
		p.ACLs[i].Src = renameInList(p.ACLs[i].Src, oldTag, newTag)
		p.ACLs[i].Dst = renameInDstList(p.ACLs[i].Dst, oldTag, newTag)
	}
	for i := range p.SSH {
		p.SSH[i].Src = renameInList(p.SSH[i].Src, oldTag, newTag)
		p.SSH[i].Dst = renameInDstList(p.SSH[i].Dst, oldTag, newTag)
	}
}

// deleteTagFromPolicy removes the tag from tagOwners and from every ACL/SSH
// rule. If a rule's src or dst becomes empty as a result, the rule itself
// is dropped (Headscale would reject an empty-src or empty-dst rule).
func deleteTagFromPolicy(p *ParsedPolicy, tag string) {
	if p == nil {
		return
	}
	delete(p.TagOwners, tag)
	p.ACLs = filterACLRules(p.ACLs, tag)
	p.SSH = filterSSHRules(p.SSH, tag)
}

func filterACLRules(rules []ACLRule, tag string) []ACLRule {
	var keep []ACLRule
	for _, r := range rules {
		r.Src = filterOut(r.Src, tag)
		r.Dst = filterOutDst(r.Dst, tag)
		if len(r.Src) == 0 || len(r.Dst) == 0 {
			continue
		}
		keep = append(keep, r)
	}
	return keep
}

func filterSSHRules(rules []SSHRule, tag string) []SSHRule {
	var keep []SSHRule
	for _, r := range rules {
		r.Src = filterOut(r.Src, tag)
		r.Dst = filterOutDst(r.Dst, tag)
		if len(r.Src) == 0 || len(r.Dst) == 0 {
			continue
		}
		keep = append(keep, r)
	}
	return keep
}

func renameInList(in []string, old, new string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		if v == old {
			out[i] = new
		} else {
			out[i] = v
		}
	}
	return out
}

func renameInDstList(in []string, old, new string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		host, port := splitHostPort(v)
		if host == old {
			host = new
		}
		if port == "" {
			out[i] = host
		} else {
			out[i] = host + ":" + port
		}
	}
	return out
}

func filterOut(in []string, x string) []string {
	out := in[:0]
	for _, v := range in {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}

func filterOutDst(in []string, x string) []string {
	out := in[:0]
	for _, v := range in {
		host, _ := splitHostPort(v)
		if host != x {
			out = append(out, v)
		}
	}
	return out
}

// countTagRefs counts how many ACL + SSH rules reference the tag (in src or dst).
func countTagRefs(p *ParsedPolicy, tag string) int {
	if p == nil {
		return 0
	}
	n := 0
	for _, r := range p.ACLs {
		for _, s := range r.Src {
			if s == tag {
				n++
				break
			}
		}
		for _, d := range r.Dst {
			host, _ := splitHostPort(d)
			if host == tag {
				n++
				break
			}
		}
	}
	for _, r := range p.SSH {
		for _, s := range r.Src {
			if s == tag {
				n++
				break
			}
		}
		for _, d := range r.Dst {
			host, _ := splitHostPort(d)
			if host == tag {
				n++
				break
			}
		}
	}
	return n
}

func sortStrings(s *[]string) {
	// stable + dedupe
	seen := map[string]bool{}
	out := (*s)[:0]
	for _, v := range *s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	*s = out
	for i := 0; i < len(*s); i++ {
		for j := i + 1; j < len(*s); j++ {
			if (*s)[j] < (*s)[i] {
				(*s)[i], (*s)[j] = (*s)[j], (*s)[i]
			}
		}
	}
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
		// Headscale rejected the policy. Re-render the page on the Raw tab
		// with the user's submitted text intact so they can fix it in place.
		bp := h.loadBase(w, r, "policy")
		pd := policyPageData{basePage: bp, RawPolicy: body, ActiveTab: "raw"}
		pd.Flash = &flash{Kind: "danger", Message: "Headscale rejected the policy: " + err.Error()}
		// Still populate Actors/Members/etc. from the currently-saved policy
		// so the Builder tab keeps working if the user clicks over.
		if pol, err2 := c.GetPolicy(ctx); err2 == nil {
			pd.Parsed = parsePolicy(pol.Policy)
			pd.UpdatedAt = pol.UpdatedAt
		}
		users, _ := c.ListUsers(ctx)
		pd.Actors, pd.Members, pd.Tags, pd.Groups = buildPolicyChoices(pd.Parsed, users)
		h.render(w, "policy.html", pd)
		return
	}
	audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "policy", nil)
	setFlash(w, "success", "Policy saved.")
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
	dstHosts := splitCSV(r.FormValue("dst_hosts"))
	port := strings.TrimSpace(r.FormValue("dst_port"))
	if len(src) == 0 || len(dstHosts) == 0 || port == "" {
		setFlash(w, "danger", "Source(s), destination(s), and port are required.")
		http.Redirect(w, r, "/policy", http.StatusSeeOther)
		return
	}
	dst := make([]string, 0, len(dstHosts))
	for _, hst := range dstHosts {
		dst = append(dst, hst+":"+port)
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
