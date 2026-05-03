package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Setup-wizard state cookie: holds the pending admin's user_id, signed with
// an HMAC key persisted in the dashboard's settings table so restarts don't
// invalidate an in-flight wizard session.

type SetupSigner struct {
	key []byte
}

// NewSetupSigner returns a signer using the supplied 32-byte key. Use
// LoadOrCreateSetupKey to fetch (or initialise) it from the settings store.
func NewSetupSigner(key []byte) *SetupSigner {
	return &SetupSigner{key: key}
}

// GenerateSetupKey returns a fresh 32-byte HMAC key. Callers persist it.
func GenerateSetupKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

func (s *SetupSigner) Sign(userID int64) string {
	body := strconv.FormatInt(userID, 10)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return body + "." + sig
}

var ErrBadSetupCookie = errors.New("bad setup cookie")

func (s *SetupSigner) Verify(value string) (int64, error) {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return 0, ErrBadSetupCookie
	}
	wantSig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, ErrBadSetupCookie
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(parts[0]))
	if !hmac.Equal(mac.Sum(nil), wantSig) {
		return 0, ErrBadSetupCookie
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, ErrBadSetupCookie
	}
	if id <= 0 {
		return 0, ErrBadSetupCookie
	}
	return id, nil
}

// FormatSecretForDisplay groups a base32 TOTP secret into 4-char blocks for legibility.
func FormatSecretForDisplay(secret string) string {
	var b strings.Builder
	for i, r := range secret {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%c", r)
	}
	return b.String()
}
