package auth

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP returns the originating client IP, parsing X-Forwarded-For
// (taking the first entry — the real client) before falling back to
// RemoteAddr. Trust the header only when the dashboard is behind a
// reverse proxy on loopback, which is the normal deploy.
func ClientIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		if i := strings.Index(x, ","); i >= 0 {
			return strings.TrimSpace(x[:i])
		}
		return strings.TrimSpace(x)
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}
