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
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`  // e.g. http://127.0.0.1:8080
	APIKey  string `json:"api_key"`
	TLSSkip bool   `json:"tls_skip"` // skip TLS verify for self-signed
}

func IsSetupComplete(d *sql.DB) (bool, error) {
	v, ok, err := db.GetSetting(d, keySetupComplete)
	if err != nil || !ok {
		return false, err
	}
	return v == "true", nil
}

func MarkSetupComplete(d *sql.DB) error {
	return db.SetSetting(d, keySetupComplete, "true")
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
