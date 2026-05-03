package dashboard

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/audit"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/headscaledb"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/settings"
)

type tagRow struct {
	Tag      string
	Owners   []string
	NodeUses int
	KeyUses  int
	RuleRefs int
	Orphan   bool // appears on a node/key but not in tagOwners
}

func (h *Handler) RegisterTagRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /tags", h.tagsPage)
	mux.HandleFunc("POST /tags/add", h.tagsAdd)
	mux.HandleFunc("POST /tags/rename", h.tagsRename)
	mux.HandleFunc("POST /tags/delete", h.tagsDelete)
}

func (h *Handler) tagsPage(w http.ResponseWriter, r *http.Request) {
	bp := h.loadBase(w, r, "tags")
	type pageData struct {
		basePage
		Rows    []tagRow
		Members []string // for "owners" picker on the Add form
	}
	pd := pageData{basePage: bp}

	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		pd.HeadscaleError = errStr
		h.render(w, "tags.html", pd)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	pol, err := c.GetPolicy(ctx)
	if err != nil {
		pd.HeadscaleError = "Could not load policy: " + err.Error()
		h.render(w, "tags.html", pd)
		return
	}
	parsed := parsePolicy(pol.Policy)

	tagSet := map[string]*tagRow{}
	if parsed != nil {
		for tag, owners := range parsed.TagOwners {
			tagSet[tag] = &tagRow{Tag: tag, Owners: owners, RuleRefs: countTagRefs(parsed, tag)}
		}
	}

	// Count node uses (from API, which already gives merged tags)
	nodes, _ := c.ListNodes(ctx, "")
	for _, n := range nodes {
		for _, t := range n.Tags {
			row, ok := tagSet[t]
			if !ok {
				row = &tagRow{Tag: t, Orphan: true, RuleRefs: countTagRefs(parsed, t)}
				tagSet[t] = row
			}
			row.NodeUses++
		}
	}
	// Count pre-auth-key uses (from API)
	keys, _ := c.ListPreAuthKeys(ctx, "")
	for _, k := range keys {
		for _, t := range k.ACLTags {
			row, ok := tagSet[t]
			if !ok {
				row = &tagRow{Tag: t, Orphan: true, RuleRefs: countTagRefs(parsed, t)}
				tagSet[t] = row
			}
			row.KeyUses++
		}
	}

	for _, r := range tagSet {
		pd.Rows = append(pd.Rows, *r)
	}
	sort.Slice(pd.Rows, func(i, j int) bool { return pd.Rows[i].Tag < pd.Rows[j].Tag })

	users, _ := c.ListUsers(ctx)
	_, members, _, _ := buildPolicyChoices(parsed, users)
	pd.Members = members

	h.render(w, "tags.html", pd)
}

// tagsAdd is a thin wrapper around the existing policyAddTagOwner logic but
// redirects back to /tags so the user sees the result there.
func (h *Handler) tagsAdd(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		setFlash(w, "danger", errStr)
		http.Redirect(w, r, "/tags", http.StatusSeeOther)
		return
	}
	tag := strings.TrimSpace(r.FormValue("tag"))
	if !strings.HasPrefix(tag, "tag:") {
		setFlash(w, "danger", "Tag must start with 'tag:'.")
		http.Redirect(w, r, "/tags", http.StatusSeeOther)
		return
	}
	owners := splitCSV(r.FormValue("owners"))
	if len(owners) == 0 {
		setFlash(w, "danger", "Owners are required.")
		http.Redirect(w, r, "/tags", http.StatusSeeOther)
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
		audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "tag.add", map[string]any{"tag": tag, "owners": owners})
		setFlash(w, "success", "Tag added.")
	}
	http.Redirect(w, r, "/tags", http.StatusSeeOther)
}

func (h *Handler) tagsRename(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	old := strings.TrimSpace(r.FormValue("old"))
	new := strings.TrimSpace(r.FormValue("new"))
	if !strings.HasPrefix(old, "tag:") || !strings.HasPrefix(new, "tag:") {
		setFlash(w, "danger", "Both names must start with 'tag:'.")
		http.Redirect(w, r, "/tags", http.StatusSeeOther)
		return
	}
	if old == new {
		http.Redirect(w, r, "/tags", http.StatusSeeOther)
		return
	}
	if err := h.applyTagOp(w, r, old, new, false); err != nil {
		setFlash(w, "danger", "Rename failed: "+err.Error())
		http.Redirect(w, r, "/tags", http.StatusSeeOther)
		return
	}
	setFlash(w, "success", "Renamed "+old+" → "+new+".")
	// Spinner waits for Headscale to come back, then lands on /tags.
	http.Redirect(w, r, "/nodes/wait?to=/tags", http.StatusSeeOther)
}

func (h *Handler) tagsDelete(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	tag := strings.TrimSpace(r.FormValue("tag"))
	if !strings.HasPrefix(tag, "tag:") {
		setFlash(w, "danger", "Tag must start with 'tag:'.")
		http.Redirect(w, r, "/tags", http.StatusSeeOther)
		return
	}
	if err := h.applyTagOp(w, r, tag, "", true); err != nil {
		setFlash(w, "danger", "Delete failed: "+err.Error())
		http.Redirect(w, r, "/tags", http.StatusSeeOther)
		return
	}
	setFlash(w, "success", "Deleted "+tag+" everywhere it was referenced.")
	http.Redirect(w, r, "/nodes/wait?to=/tags", http.StatusSeeOther)
}

// applyTagOp walks the policy + Headscale's nodes.tags + pre_auth_keys.tags,
// applies a rename (delete=false) or removal (delete=true), saves the policy,
// and restarts Headscale. Requires HeadscaleDB to be enabled — without it we
// can't touch nodes.tags / pre_auth_keys.tags.
func (h *Handler) applyTagOp(w http.ResponseWriter, r *http.Request, old, newTag string, deleteOp bool) error {
	c, errStr := h.headscaleClient(r.Context())
	if c == nil {
		return errf(errStr)
	}
	hdb, _ := settings.GetHeadscaleDB(h.db)
	if !hdb.Enabled || hdb.Path == "" {
		return errf("Local Headscale DB is not enabled — required to rewrite node/key tags. Enable in Settings → Headscale local DB.")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// 1. Update policy (server-side)
	if err := h.loadAndMutate(ctx, c, func(p *ParsedPolicy) {
		if deleteOp {
			deleteTagFromPolicy(p, old)
		} else {
			renameTagInPolicy(p, old, newTag)
		}
	}); err != nil {
		return err
	}

	// 2. Rewrite nodes.tags + pre_auth_keys.tags
	hdbClient := headscaledb.New(hdb)
	transform := func(in []string) []string {
		if deleteOp {
			out := in[:0]
			for _, v := range in {
				if v != old {
					out = append(out, v)
				}
			}
			return out
		}
		out := make([]string, len(in))
		for i, v := range in {
			if v == old {
				out[i] = newTag
			} else {
				out[i] = v
			}
		}
		return out
	}
	nNodes, err := hdbClient.RewriteTags("nodes", transform)
	if err != nil {
		return err
	}
	nKeys, err := hdbClient.RewriteTags("pre_auth_keys", transform)
	if err != nil {
		return err
	}

	// 3. Restart Headscale so the in-memory NetMap reloads
	if _, err := hdbClient.RestartHeadscale(); err != nil {
		return err
	}

	verb := "rename"
	if deleteOp {
		verb = "delete"
	}
	audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "tag."+verb, map[string]any{
		"old": old, "new": newTag, "nodes_updated": nNodes, "keys_updated": nKeys,
	})
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }
func errf(s string) error         { return errString(s) }

