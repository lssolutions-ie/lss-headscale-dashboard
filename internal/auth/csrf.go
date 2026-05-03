package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
)

const (
	csrfCookieName = "lss_csrf"
	// CSRFCookieMaxAge matches the session lifetime so a long-open tab doesn't
	// silently fail CSRF when the cookie outlives its old 1-hour value.
	CSRFCookieMaxAge = int(SessionDuration / 1e9) // seconds
)

// EnsureCSRFToken returns the existing CSRF cookie value or mints a fresh one.
// Refreshes the cookie on every call so MaxAge slides forward; the same token
// stays valid for the entire session.
func EnsureCSRFToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && len(c.Value) >= 24 {
		setCSRFCookie(w, r, c.Value)
		return c.Value
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// Surface as best we can; caller should treat this as a 500 — without
		// CSRF we'd be writing forms that can't be validated.
		panic(errors.New("auth: rand.Read failed in CSRF token generation"))
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	setCSRFCookie(w, r, tok)
	return tok
}

func setCSRFCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.Header.Get("X-Forwarded-Proto") == "https",
		MaxAge:   CSRFCookieMaxAge,
	})
}

// CheckCSRFToken returns true if the request's `csrf` form value matches its
// CSRF cookie. False on missing cookie, missing value, or mismatch.
func CheckCSRFToken(r *http.Request) bool {
	c, err := r.Cookie(csrfCookieName)
	if err != nil {
		return false
	}
	v := r.FormValue("csrf")
	if v == "" {
		v = r.Header.Get("X-CSRF")
	}
	return v != "" && v == c.Value
}
