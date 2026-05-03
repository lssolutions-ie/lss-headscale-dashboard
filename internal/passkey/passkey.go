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
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Handler struct {
	db           *sql.DB
	log          *slog.Logger
	pending      map[int64]*pendingSession  // registration sessions, keyed by user id
	pendingLogin map[string]*pendingSession // login sessions, keyed by random token
	pendingMu    sync.Mutex
}

type pendingSession struct {
	session   webauthn.SessionData
	createdAt time.Time
}

// pendingTTL is how long a Begin* without a matching Finish* is kept around
// before the sweeper drops it. WebAuthn ceremonies don't take this long.
const pendingTTL = 5 * time.Minute

func New(d *sql.DB, log *slog.Logger) *Handler {
	h := &Handler{
		db:           d,
		log:          log,
		pending:      map[int64]*pendingSession{},
		pendingLogin: map[string]*pendingSession{},
	}
	// Background sweeper so half-completed ceremonies don't pile up forever.
	// (We also check the per-entry timestamp on Finish, but a never-finished
	// session would otherwise live for the lifetime of the process.)
	go func() {
		t := time.NewTicker(pendingTTL)
		defer t.Stop()
		for range t.C {
			h.sweepPending()
		}
	}()
	return h
}

func (h *Handler) sweepPending() {
	cutoff := time.Now().Add(-pendingTTL)
	h.pendingMu.Lock()
	defer h.pendingMu.Unlock()
	for k, ps := range h.pending {
		if ps.createdAt.Before(cutoff) {
			delete(h.pending, k)
		}
	}
	for k, ps := range h.pendingLogin {
		if ps.createdAt.Before(cutoff) {
			delete(h.pendingLogin, k)
		}
	}
}

func newToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

const loginCookie = "lss_pk_login"

// rpFromRequest returns the WebAuthn config derived from the request's host.
//
// Scheme detection:
//   - If X-Forwarded-Proto is set, trust it (HAProxy / nginx setups).
//   - Else if the request arrived directly over TLS, use https.
//   - Else if the host is a loopback (localhost / 127.0.0.1 / ::1), use http
//     (matches SSH-tunnel access at http://localhost:9000).
//   - Else default to https. Reverse proxies that don't set X-Forwarded-Proto
//     are common; a real hostname effectively always means TLS in front in
//     production. The previous heuristic defaulted to http and broke
//     mgmt.example.com setups whose proxy didn't pass the header.
func rpFromRequest(r *http.Request) (*webauthn.WebAuthn, error) {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	rpID := strings.SplitN(host, ":", 2)[0]

	scheme := "https"
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = xfp
	} else if r.TLS != nil {
		scheme = "https"
	} else if isLoopback(rpID) {
		scheme = "http"
	}
	origin := scheme + "://" + host
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "LSS Headscale Dashboard",
		RPOrigins:     []string{origin},
	})
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasPrefix(host, "127.")
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
		SELECT credential_id, public_key, sign_count, COALESCE(aaguid, X''),
		       backup_eligible, backup_state
		FROM webauthn_credentials WHERE user_id = ?
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c webauthn.Credential
		var aaguid []byte
		var beEligible, beState bool
		if err := rows.Scan(&c.ID, &c.PublicKey, &c.Authenticator.SignCount, &aaguid, &beEligible, &beState); err != nil {
			return nil, err
		}
		c.Authenticator.AAGUID = aaguid
		c.Flags.BackupEligible = beEligible
		c.Flags.BackupState = beState
		u.creds = append(u.creds, c)
	}
	return u, nil
}

// BeginRegister returns the PublicKeyCredentialCreationOptions for a new credential.
//
// Requests a resident (discoverable) credential so Bitwarden, Yubikey, passkey
// providers etc. can list this dashboard at sign-in time without needing the
// username typed first. UserVerification is preferred but not required so
// hardware keys without PINs still work.
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
	options, session, err := wa.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
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

// BeginLogin starts a passwordless WebAuthn assertion. The browser shows the
// user every passkey it has for this site; no username required.
func (h *Handler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	wa, err := rpFromRequest(r)
	if err != nil {
		writeErr(w, 500, "rp config: "+err.Error())
		return
	}
	options, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		writeErr(w, 500, "begin login: "+err.Error())
		return
	}
	tok := newToken()
	h.pendingMu.Lock()
	h.pendingLogin[tok] = &pendingSession{session: *session, createdAt: time.Now()}
	h.pendingMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     loginCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
		Secure:   r.Header.Get("X-Forwarded-Proto") == "https",
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(options)
}

// FinishLogin verifies the assertion and returns the user_id of the user the
// matching credential belongs to. Caller is responsible for creating the
// auth session cookie.
func (h *Handler) FinishLogin(r *http.Request) (int64, error) {
	wa, err := rpFromRequest(r)
	if err != nil {
		return 0, fmt.Errorf("rp config: %w", err)
	}
	c, err := r.Cookie(loginCookie)
	if err != nil {
		return 0, errors.New("no pending login (cookie missing)")
	}
	h.pendingMu.Lock()
	ps := h.pendingLogin[c.Value]
	delete(h.pendingLogin, c.Value)
	h.pendingMu.Unlock()
	if ps == nil || time.Since(ps.createdAt) > 5*time.Minute {
		return 0, errors.New("no pending login (expired)")
	}
	// The browser returns userHandle (= what we set as WebAuthnID() during
	// register, which is the user.id formatted as ASCII decimal). Use that to
	// look up the user.
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		uid, err := strconv.ParseInt(string(userHandle), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad user handle %q", string(userHandle))
		}
		return loadUser(h.db, uid)
	}
	cred, err := wa.FinishDiscoverableLogin(handler, ps.session, r)
	if err != nil {
		return 0, fmt.Errorf("verify: %w", err)
	}
	// Update sign_count + last_used_at for replay protection / audit.
	var userID int64
	err = h.db.QueryRow(
		`SELECT user_id FROM webauthn_credentials WHERE credential_id = ?`,
		cred.ID,
	).Scan(&userID)
	if err != nil {
		return 0, fmt.Errorf("look up credential: %w", err)
	}
	if _, err := h.db.Exec(
		`UPDATE webauthn_credentials SET sign_count = ?, last_used_at = CURRENT_TIMESTAMP WHERE credential_id = ?`,
		cred.Authenticator.SignCount, cred.ID,
	); err != nil {
		// Replay protection depends on this advancing — surface failures so a
		// stuck count is visible in journald, even if we still let the login
		// succeed (the user just authenticated successfully).
		h.log.Error("passkey: sign_count update failed", "err", err, "user_id", userID)
	}
	return userID, nil
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
		expected, _ := rpFromRequest(r)
		var rpOrigins []string
		if expected != nil {
			rpOrigins = expected.Config.RPOrigins
		}
		h.log.Warn("webauthn register verify failed",
			"err", err,
			"expected_rpid_and_origins", rpOrigins,
			"client_data_origin", parsed.Response.CollectedClientData.Origin,
			"x_forwarded_proto", r.Header.Get("X-Forwarded-Proto"),
			"host", r.Host)
		writeErr(w, 400, "verify: "+err.Error())
		return
	}
	if _, err := h.db.Exec(`
		INSERT INTO webauthn_credentials (
			user_id, credential_id, public_key, sign_count, aaguid, label,
			backup_eligible, backup_state
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, userID, cred.ID, cred.PublicKey, cred.Authenticator.SignCount, cred.Authenticator.AAGUID, label,
		cred.Flags.BackupEligible, cred.Flags.BackupState); err != nil {
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

