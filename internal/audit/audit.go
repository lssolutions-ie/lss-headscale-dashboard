package audit

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"time"
)

const (
	ActionLoginSuccess     = "auth.login.success"
	ActionLoginFailure     = "auth.login.failure"
	ActionLogout           = "auth.logout"
	ActionPasswordChange   = "auth.password.change"
	ActionSettingsUpdate   = "settings.update"
	ActionSMTPTest         = "smtp.test"
	ActionUserCreate       = "headscale.user.create"
	ActionUserDelete       = "headscale.user.delete"
	ActionNodeExpire       = "headscale.node.expire"
	ActionNodeDelete       = "headscale.node.delete"
	ActionPreAuthKeyCreate = "headscale.preauthkey.create"
	ActionPreAuthKeyExpire = "headscale.preauthkey.expire"
)

type Entry struct {
	ID          int64
	ActorUserID *int64
	IP          string
	Action      string
	Target      string
	Details     string
	Timestamp   time.Time
}

func Write(d *sql.DB, actorUserID *int64, ip, action, target string, details map[string]any) {
	var detailsJSON string
	if details != nil {
		b, _ := json.Marshal(details)
		detailsJSON = string(b)
	}
	_, err := d.Exec(`
		INSERT INTO audit_log (actor_user_id, ip, action, target, details_json)
		VALUES (?, ?, ?, ?, ?)
	`, actorUserID, ip, action, target, detailsJSON)
	if err != nil {
		// The audit log is the chief forensics record; a silent failure leaves
		// no trace. Surface to journald even though we can't tell the caller.
		slog.Error("audit write failed", "err", err, "action", action, "target", target)
	}
}

// List returns the most recent audit entries (newest first), paginated.
func List(d *sql.DB, limit, offset int) ([]Entry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := d.Query(`
		SELECT id, actor_user_id, COALESCE(ip,''), action, COALESCE(target,''), COALESCE(details_json,''), ts
		FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var actor sql.NullInt64
		if err := rows.Scan(&e.ID, &actor, &e.IP, &e.Action, &e.Target, &e.Details, &e.Timestamp); err != nil {
			return nil, err
		}
		if actor.Valid {
			a := actor.Int64
			e.ActorUserID = &a
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

