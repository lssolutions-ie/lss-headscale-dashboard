package auth

import (
	"context"
	"database/sql"
	"net/http"
)

type ctxKey int

const (
	ctxSession ctxKey = iota
	ctxUser
)

func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, ctxSession, s)
}

func SessionFrom(ctx context.Context) *Session {
	if s, ok := ctx.Value(ctxSession).(*Session); ok {
		return s
	}
	return nil
}

// RequireAuth wraps a handler so that requests without a valid session redirect to /login.
func RequireAuth(d *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(SessionCookieName)
			if err != nil {
				redirectToLogin(w, r)
				return
			}
			s, err := LookupSession(d, c.Value)
			if err != nil {
				ClearSessionCookie(w)
				redirectToLogin(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithSession(r.Context(), s)))
		})
	}
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
