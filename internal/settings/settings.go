// Package settings provides typed read/write of application settings stored in the
// SQLite settings KV table. Used for SMTP and Headscale connection config that's
// edited through the wizard / admin UI rather than config.yaml.
package settings

import (
	"database/sql"
	"encoding/json"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/db"
)

const (
	keySetupComplete = "setup_complete"
	keySMTP          = "smtp"
	keyHeadscale     = "headscale"
	keyHeadscaleDB = "headscale_db"
)

type SMTP struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	TLS      string `json:"tls"` // none | starttls | tls
}

type Headscale struct {
	Enabled   bool   `json:"enabled"`
	Address   string `json:"address"`    // API URL, e.g. http://127.0.0.1:8080
	APIKey    string `json:"api_key"`
	TLSSkip   bool   `json:"tls_skip"`   // skip TLS verify for self-signed
	ClientURL string `json:"client_url"` // public URL Tailscale clients use (server_url)
}

// HeadscaleDB is the local-filesystem path to Headscale's SQLite DB plus the
// command used to restart Headscale after writing. Used for fields Headscale's
// HTTP API does not expose (ipv4, ipv6, raw hostname). The dashboard must run
// on the same host as Headscale and have read/write access to the DB file
// (via the `headscale` group, which install.sh handles).
type HeadscaleDB struct {
	Enabled    bool   `json:"enabled"`
	Path       string `json:"path"`
	RestartCmd string `json:"restart_cmd"`
}

func IsSetupComplete(d *sql.DB) (bool, error) {
	v, ok, err := db.GetSetting(d, keySetupComplete)
	if err != nil || !ok {
		return false, err
	}
	return v == "true", nil
}

func GetSMTP(d *sql.DB) (SMTP, error) {
	var s SMTP
	v, ok, err := db.GetSetting(d, keySMTP)
	if err != nil || !ok {
		return s, err
	}
	if err := json.Unmarshal([]byte(v), &s); err != nil {
		return s, err
	}
	return s, nil
}

func SaveSMTP(d *sql.DB, s SMTP) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.SetSetting(d, keySMTP, string(b))
}

func GetHeadscale(d *sql.DB) (Headscale, error) {
	var h Headscale
	v, ok, err := db.GetSetting(d, keyHeadscale)
	if err != nil || !ok {
		return h, err
	}
	if err := json.Unmarshal([]byte(v), &h); err != nil {
		return h, err
	}
	return h, nil
}

func SaveHeadscale(d *sql.DB, h Headscale) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return db.SetSetting(d, keyHeadscale, string(b))
}

func GetHeadscaleDB(d *sql.DB) (HeadscaleDB, error) {
	var h HeadscaleDB
	v, ok, err := db.GetSetting(d, keyHeadscaleDB)
	if err != nil || !ok {
		return h, err
	}
	if err := json.Unmarshal([]byte(v), &h); err != nil {
		return h, err
	}
	return h, nil
}

func SaveHeadscaleDB(d *sql.DB, h HeadscaleDB) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return db.SetSetting(d, keyHeadscaleDB, string(b))
}
