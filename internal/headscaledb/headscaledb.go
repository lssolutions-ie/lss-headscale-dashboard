// Package headscaledb writes columns Headscale's HTTP API does not expose
// (ipv4, ipv6, raw hostname) directly to its local SQLite DB, and restarts
// the headscale service so the in-memory NetMap reloads.
//
// Only used when the dashboard runs co-located with Headscale on the same
// host and the operator has explicitly enabled HeadscaleDB in /settings.
// Column names are whitelisted; we never accept dynamic column input.
package headscaledb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/settings"
)

var (
	jsonMarshal   = json.Marshal
	jsonUnmarshal = json.Unmarshal
)

const DefaultPath = "/var/lib/headscale/db.sqlite"
const DefaultRestartCmd = "sudo -n /usr/bin/systemctl restart headscale.service"

// AllowedColumns is the list of columns the dashboard will write to the
// nodes table. Includes every column in Headscale 0.28's schema; the user
// is responsible for the consequences of editing crypto keys, FKs, or
// timestamps.
var AllowedColumns = []string{
	"id", "machine_key", "node_key", "disco_key",
	"endpoints", "host_info",
	"ipv4", "ipv6",
	"hostname", "given_name",
	"user_id", "register_method", "tags", "auth_key_id",
	"last_seen", "expiry", "approved_routes",
	"created_at", "updated_at", "deleted_at",
}

var allowedColumns = func() map[string]bool {
	m := map[string]bool{}
	for _, c := range AllowedColumns {
		m[c] = true
	}
	return m
}()

type Client struct {
	cfg settings.HeadscaleDB
}

func New(cfg settings.HeadscaleDB) *Client { return &Client{cfg: cfg} }

func (c *Client) open() (*sql.DB, error) {
	if c.cfg.Path == "" {
		return nil, errors.New("path not configured")
	}
	dsn := "file:" + c.cfg.Path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	if err := d.Ping(); err != nil {
		_ = d.Close()
		return nil, err
	}
	return d, nil
}

// FullNode is every column in the nodes table as a string (NULL → "").
// Returned by ListFullNodes so the Edit modal can populate every input.
type FullNode map[string]string

// ListFullNodes returns one FullNode per row, keyed by the row's id (as string).
// All columns are returned as strings; NULLs become "".
func (c *Client) ListFullNodes() (map[string]FullNode, error) {
	d, err := c.open()
	if err != nil {
		return nil, err
	}
	defer d.Close()
	cols := strings.Join(quoteColumns(AllowedColumns), ", ")
	rows, err := d.Query("SELECT " + cols + " FROM nodes WHERE deleted_at IS NULL")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]FullNode{}
	for rows.Next() {
		vals := make([]any, len(AllowedColumns))
		ptrs := make([]any, len(AllowedColumns))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		fn := FullNode{}
		for i, col := range AllowedColumns {
			fn[col] = toString(vals[i])
		}
		out[fn["id"]] = fn
	}
	return out, rows.Err()
}

// quoteColumns wraps `tags` (a SQLite reserved word) in double-quotes; others
// pass through. SQLite is fine with quoting non-reserved names too but we keep
// the SQL readable.
func quoteColumns(cols []string) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		if c == "tags" {
			out[i] = `"tags"`
		} else {
			out[i] = c
		}
	}
	return out
}

func toString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case time.Time:
		return x.Format("2006-01-02 15:04:05")
	default:
		return fmt.Sprintf("%v", x)
	}
}

// Test verifies the file is reachable and the nodes table exists.
func (c *Client) Test() error {
	d, err := c.open()
	if err != nil {
		return err
	}
	defer d.Close()
	var n int
	return d.QueryRow("SELECT COUNT(*) FROM nodes").Scan(&n)
}

// UpdateNodeFields runs an UPDATE for the whitelisted columns supplied.
// Returns the number of rows affected and any error.
func (c *Client) UpdateNodeFields(nodeID string, fields map[string]string) (int64, error) {
	if len(fields) == 0 {
		return 0, errors.New("no fields to update")
	}
	id, err := strconv.Atoi(nodeID)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("bad node id: %q", nodeID)
	}
	var sets []string
	var args []any
	for col, val := range fields {
		if !allowedColumns[col] {
			return 0, fmt.Errorf("refusing to update column %q", col)
		}
		sets = append(sets, col+" = ?")
		args = append(args, val)
	}
	d, err := c.open()
	if err != nil {
		return 0, err
	}
	defer d.Close()
	// updated_at is also a writable column; only auto-touch it when the
	// caller didn't pass one explicitly.
	if _, explicit := fields["updated_at"]; !explicit {
		sets = append(sets, "updated_at = ?")
		args = append(args, time.Now().UTC().Format("2006-01-02 15:04:05"))
	}
	args = append(args, id)
	stmt := "UPDATE nodes SET " + strings.Join(sets, ", ") + " WHERE id = ?"
	res, err := d.Exec(stmt, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// rewriteTagsTables is a single-table-name whitelist; pass anything else and
// the call refuses to run. Both Headscale tables that store a JSON-encoded
// list of tags use the column name "tags".
var rewriteTagsTables = map[string]bool{"nodes": true, "pre_auth_keys": true}

// RewriteTags walks a tag-bearing table and rewrites the JSON tag list per
// row using `f`. Returns the number of rows actually changed.
//
// Use case: rename a tag everywhere it appears, or delete it. The function
// parses the existing JSON, calls f, marshals the new list, and updates only
// when the list actually changed.
func (c *Client) RewriteTags(table string, f func([]string) []string) (int64, error) {
	if !rewriteTagsTables[table] {
		return 0, fmt.Errorf("refusing to rewrite tags in table %q", table)
	}
	d, err := c.open()
	if err != nil {
		return 0, err
	}
	defer d.Close()

	type row struct {
		id   int64
		tags string
	}
	rs, err := d.Query("SELECT id, COALESCE(tags, '') FROM " + table)
	if err != nil {
		return 0, err
	}
	var rows []row
	for rs.Next() {
		var r row
		if err := rs.Scan(&r.id, &r.tags); err != nil {
			rs.Close()
			return 0, err
		}
		rows = append(rows, r)
	}
	rs.Close()

	tx, err := d.Begin()
	if err != nil {
		return 0, err
	}
	var changed int64
	for _, r := range rows {
		var current []string
		if r.tags != "" {
			if err := jsonUnmarshalTags(r.tags, &current); err != nil {
				continue
			}
		}
		next := f(append([]string(nil), current...))
		if stringSlicesEqual(current, next) {
			continue
		}
		var nextJSON string
		if len(next) > 0 {
			b, err := jsonMarshalTags(next)
			if err != nil {
				_ = tx.Rollback()
				return changed, err
			}
			nextJSON = b
		}
		if _, err := tx.Exec("UPDATE "+table+" SET tags = ? WHERE id = ?", nullIfEmpty(nextJSON), r.id); err != nil {
			_ = tx.Rollback()
			return changed, err
		}
		changed++
	}
	if err := tx.Commit(); err != nil {
		return changed, err
	}
	return changed, nil
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// jsonMarshal/Unmarshal as helpers so the file doesn't need encoding/json
// imported at the top (which would be inconsistent with the rest of the
// package's bare imports).
func jsonMarshalTags(v []string) (string, error) {
	b, err := jsonMarshal(v)
	return string(b), err
}
func jsonUnmarshalTags(s string, v *[]string) error { return jsonUnmarshal([]byte(s), v) }

// RestartHeadscale runs the configured restart command (default uses sudo +
// systemctl). Returns combined stdout/stderr and any error.
func (c *Client) RestartHeadscale() (string, error) {
	cmd := c.cfg.RestartCmd
	if cmd == "" {
		cmd = DefaultRestartCmd
	}
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "", errors.New("empty restart command")
	}
	out, err := exec.Command(parts[0], parts[1:]...).CombinedOutput()
	return string(out), err
}
