// Package web serves the bundled static assets (Tabler.io + HTMX) so the
// dashboard works without internet egress to a CDN.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFS embed.FS

// Handler returns an http.Handler that serves /static/* from the embedded
// directory. Mount with:
//
//	mux.Handle("GET /static/", web.Handler())
func Handler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // baked-in subdir, can't fail
	}
	fs := http.FileServer(http.FS(sub))
	return http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Cache aggressively — these are versioned by binary, never change at runtime.
		w.Header().Set("Cache-Control", "public, max-age=2592000, immutable")
		fs.ServeHTTP(w, r)
	}))
}
