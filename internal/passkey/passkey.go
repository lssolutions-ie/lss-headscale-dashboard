// Package passkey wires the go-webauthn library into the dashboard.
//
// IMPORTANT: WebAuthn requires HTTPS in browsers (loopback excepted). The
// dashboard ships with HTTP only by design — TLS is HAProxy's job. To use
// passkeys / Yubikeys, deploy HAProxy in front and access the dashboard via
// HTTPS. The RP ID and origin must match the hostname users see in their
// browser; both are derived per-request from the Host / X-Forwarded-Host
// headers, so the same install can serve multiple hostnames.
package passkey

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Handler struct {
	db        *sql.DB
	log       *slog.Logger
	pending   map[int64]*pendingSession
	pendingMu sync.Mutex
}

type pendingSession struct {
	session   webauthn.SessionData
	createdAt time.Time
}

func New(d *sql.DB, log *slog.Logger) *Handler {
	return &Handler{db: d, log: log, pending: map[int64]*pendingSession{}}
}

// rpFromRequest returns the WebAuthn config derived from the request's
// host (so the same binary works regardless of hostname).
func rpFromRequest(r *http.Request) (*webauthn.WebAuthn, error) {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	rpID := strings.SplitN(host, ":", 2)[0]
	scheme := "https"
	if r.Header.Get("X-Forwarded-Proto") == "http" || (r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "") {
		scheme = "http"
	}
	origin := scheme + "://" + host
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "LSS Headscale Dashboard",
		RPOrigins:     []string{origin},
	})
}

// userAdapter implements webauthn.User against our DB row.
type userAdapter struct {
	id       int64
	username string
	creds    []webauthn.Credential
}

func (u *userAdapter) WebAuthnID() []byte {
	return []byte(fmt.Sprintf("%d", u.id))
}
func (u *userAdapter) WebAuthnName() string                  { return u.username }
func (u *userAdapter) WebAuthnDisplayName() string           { return u.username }
func (u *userAdapter) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func loadUser(d *sql.DB, userID int64) (*userAdapter, error) {
	u := &userAdapter{id: userID}
	if err := d.QueryRow(`SELECT username FROM users WHERE id = ?`, userID).Scan(&u.username); err != nil {
		return nil, err
	}
	rows, err := d.Query(`
		SELECT credential_id, public_key, sign_count, COALESCE(aaguid, X'')
		FROM webauthn_credentials WHERE user_id = ?
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c webauthn.Credential
		var aaguid []byte
		if err := rows.Scan(&c.ID, &c.PublicKey, &c.Authenticator.SignCount, &aaguid); err != nil {
			return nil, err
		}
		c.Authenticator.AAGUID = aaguid
		u.creds = append(u.creds, c)
	}
	return u, nil
}

// BeginRegister returns the PublicKeyCredentialCreationOptions for a new credential.
func (h *Handler) BeginRegister(w http.ResponseWriter, r *http.Request, userID int64) {
	wa, err := rpFromRequest(r)
	if err != nil {
		writeErr(w, 500, "rp config: "+err.Error())
		return
	}
	user, err := loadUser(h.db, userID)
	if err != nil {
		writeErr(w, 500, "load user: "+err.Error())
		return
	}
	options, session, err := wa.BeginRegistration(user)
	if err != nil {
		writeErr(w, 500, "begin: "+err.Error())
		return
	}
	h.pendingMu.Lock()
	h.pending[userID] = &pendingSession{session: *session, createdAt: time.Now()}
	h.pendingMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(options)
}

// FinishRegister verifies the attestation and stores the new credential.
func (h *Handler) FinishRegister(w http.ResponseWriter, r *http.Request, userID int64, label string) {
	wa, err := rpFromRequest(r)
	if err != nil {
		writeErr(w, 500, "rp config: "+err.Error())
		return
	}
	user, err := loadUser(h.db, userID)
	if err != nil {
		writeErr(w, 500, "load user: "+err.Error())
		return
	}
	h.pendingMu.Lock()
	ps := h.pending[userID]
	delete(h.pending, userID)
	h.pendingMu.Unlock()
	if ps == nil || time.Since(ps.createdAt) > 5*time.Minute {
		writeErr(w, 400, "no pending registration; try again")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		writeErr(w, 400, "parse: "+err.Error())
		return
	}
	cred, err := wa.CreateCredential(user, ps.session, parsed)
	if err != nil {
		writeErr(w, 400, "verify: "+err.Error())
		return
	}
	if _, err := h.db.Exec(`
		INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, aaguid, label)
		VALUES (?, ?, ?, ?, ?, ?)
	`, userID, cred.ID, cred.PublicKey, cred.Authenticator.SignCount, cred.Authenticator.AAGUID, label); err != nil {
		writeErr(w, 500, "save: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) DeleteCredential(userID, credID int64) error {
	res, err := h.db.Exec(`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`, credID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("credential not found")
	}
	return nil
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
}

// (kept for the "Settings → Passkeys" UI; the JS client base64url-encodes
// IDs so the server treats them as []byte directly via Decode helpers).
var _ = base64.RawURLEncoding
