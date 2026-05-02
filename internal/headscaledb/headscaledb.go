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
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/settings"
)

const DefaultPath = "/var/lib/headscale/db.sqlite"
const DefaultRestartCmd = "sudo -n /usr/bin/systemctl restart headscale.service"

var allowedColumns = map[string]bool{
	"id":         true,
	"ipv4":       true,
	"ipv6":       true,
	"hostname":   true,
	"given_name": true,
}

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
	args = append(args, id)
	d, err := c.open()
	if err != nil {
		return 0, err
	}
	defer d.Close()
	stmt := "UPDATE nodes SET " + strings.Join(sets, ", ") + ", updated_at = ? WHERE id = ?"
	args = append(args[:len(args)-1], time.Now().UTC().Format("2006-01-02 15:04:05"), id)
	res, err := d.Exec(stmt, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

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
