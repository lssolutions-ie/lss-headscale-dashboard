package dashboard

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/audit"
)

// registerPreset is the view-model for a saved Register Node form.
// Values is decoded JSON of the form's name→value map; the template
// hands it to the JS layer which fills the form on selection.
type registerPreset struct {
	ID     int64             `json:"id"`
	Name   string            `json:"name"`
	Values map[string]string `json:"values"`
}

// loadRegisterPresets reads all saved presets ordered by name.
func loadRegisterPresets(db *sql.DB) ([]registerPreset, error) {
	rows, err := db.Query(`SELECT id, name, values_json FROM register_presets ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []registerPreset
	for rows.Next() {
		var p registerPreset
		var raw string
		if err := rows.Scan(&p.ID, &p.Name, &raw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(raw), &p.Values)
		out = append(out, p)
	}
	return out, rows.Err()
}

// presetFieldsToCapture lists the form fields a preset stores. Anything
// not listed (csrf, expiration as a wall-clock datetime) is intentionally
// skipped — presets are templates, not snapshots.
var presetFieldsToCapture = []string{
	"user", "hostname", "tags",
	"reusable", "ephemeral",
	"login_server",
	"accept_dns", "accept_routes",
	"advertise_exit_node", "advertise_routes",
	"exit_node", "exit_node_lan",
	"reset", "force_reauth", "unattended", "shields_up", "ssh",
	"timeout", "operator", "nickname",
	"netfilter_mode", "snat_subnet_routes", "stateful_filtering", "accept_risk",
}

func (h *Handler) nodesRegisterPresetSave(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("preset_name"))
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "preset name required"})
		return
	}
	if len(name) > 80 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "preset name too long (max 80)"})
		return
	}
	values := make(map[string]string, len(presetFieldsToCapture))
	for _, f := range presetFieldsToCapture {
		if v := r.FormValue(f); v != "" {
			values[f] = v
		}
	}
	raw, err := json.Marshal(values)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	// Upsert by name.
	_, err = h.db.Exec(`
		INSERT INTO register_presets (name, values_json, created_by)
		VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET values_json = excluded.values_json, updated_at = CURRENT_TIMESTAMP
	`, name, string(raw), actorID(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "register_preset.save", map[string]any{"name": name})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
}

func (h *Handler) nodesRegisterPresetDelete(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "id required"})
		return
	}
	if _, err := h.db.Exec(`DELETE FROM register_presets WHERE id = ?`, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	audit.Write(h.db, actorID(r), currentIP(r), audit.ActionSettingsUpdate, "register_preset.delete", map[string]any{"id": id})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
