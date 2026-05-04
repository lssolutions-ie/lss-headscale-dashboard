package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/auth"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/dashboard"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/db"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/login"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/passkey"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/settings"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/setup"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/web"
)

var (
	version = "dev"
	commit  = "none"
)

type Config struct {
	Listen   string `yaml:"listen"`
	DataDir  string `yaml:"data_dir"`
	LogLevel string `yaml:"log_level"`
}

func defaultConfig() Config {
	return Config{
		Listen:   "0.0.0.0:9000",
		DataDir:  "/var/lib/lss-headscale-dashboard",
		LogLevel: "info",
	}
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// startBackgroundCleanup periodically purges old auth_failures + expired sessions.
func startBackgroundCleanup(ctx context.Context, d *sql.DB) {
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = auth.PurgeOldAuthFailures(d)
				_ = auth.PurgeExpiredSessions(d)
			}
		}
	}()
}

func main() {
	configPath := flag.String("config", "", "path to config.yaml")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		slog.Error("config load failed", "path", *configPath, "err", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(cfg.LogLevel),
	}))
	slog.SetDefault(logger)

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		logger.Error("create data dir", "path", cfg.DataDir, "err", err)
		os.Exit(1)
	}
	dbPath := filepath.Join(cfg.DataDir, "dashboard.db")
	d, err := db.Open(dbPath)
	if err != nil {
		logger.Error("open db", "path", dbPath, "err", err)
		os.Exit(1)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		logger.Error("migrate db", "err", err)
		os.Exit(1)
	}

	// --- Setup wizard handler (only routes used while setup_complete=false) ---
	// Load or create a persistent HMAC key so in-flight wizard sessions
	// survive a service restart.
	const setupKeyName = "setup_signing_key"
	keyB64, _, err := db.GetSetting(d, setupKeyName)
	if err != nil {
		logger.Error("read setup key", "err", err)
		os.Exit(1)
	}
	var signingKey []byte
	if keyB64 == "" {
		signingKey, err = auth.GenerateSetupKey()
		if err != nil {
			logger.Error("generate setup key", "err", err)
			os.Exit(1)
		}
		if err := db.SetSetting(d, setupKeyName, base64.StdEncoding.EncodeToString(signingKey)); err != nil {
			logger.Error("persist setup key", "err", err)
			os.Exit(1)
		}
	} else {
		signingKey, err = base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			logger.Error("decode setup key", "err", err)
			os.Exit(1)
		}
	}
	signer := auth.NewSetupSigner(signingKey)
	setupH, err := setup.New(d, signer, logger)
	if err != nil {
		logger.Error("setup handler", "err", err)
		os.Exit(1)
	}

	// --- Dashboard handler (post-login routes) ---
	dashH, err := dashboard.New(d, logger)
	if err != nil {
		logger.Error("dashboard handler", "err", err)
		os.Exit(1)
	}

	// --- Login handler (uses dashboard's base.html for layout) ---
	loginH, err := login.New(d, logger, dashboard.TemplateFS, dashboard.TemplateGlob)
	if err != nil {
		logger.Error("login handler", "err", err)
		os.Exit(1)
	}

	// --- Passkey (WebAuthn) handler ---
	pkH := passkey.New(d, logger)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})

	// Vendored Tabler + HTMX. Public so the login page (pre-auth) can load
	// styles too. Cached aggressively — versioned by binary.
	mux.Handle("GET /static/", web.Handler())

	// Setup wizard routes are always mounted; once setup_complete=true the
	// wizard handlers redirect to /login (handled inside setup.Handler).
	setupH.Routes(mux)

	loginH.Routes(mux)
	loginH.RegisterResetRoutes(mux)

	// Passkey-based login (public — no session yet).
	mux.HandleFunc("POST /login/passkey/begin", pkH.BeginLogin)
	mux.HandleFunc("POST /login/passkey/finish", func(w http.ResponseWriter, r *http.Request) {
		userID, err := pkH.FinishLogin(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		s, err := auth.CreateSession(d, userID, auth.ClientIP(r), r.UserAgent())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		auth.SetSessionCookie(w, r, s.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "redirect": "/"})
	})

	// Authenticated dashboard routes — wrapped in RequireAuth.
	authMW := auth.RequireAuth(d)
	dashMux := http.NewServeMux()
	dashH.Routes(dashMux)
	// Passkey endpoints (also authenticated).
	dashMux.HandleFunc("POST /settings/passkeys/register/begin", func(w http.ResponseWriter, r *http.Request) {
		s := auth.SessionFrom(r.Context())
		if s == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		pkH.BeginRegister(w, r, s.UserID)
	})
	dashMux.HandleFunc("POST /settings/passkeys/register/finish", func(w http.ResponseWriter, r *http.Request) {
		s := auth.SessionFrom(r.Context())
		if s == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		label := r.URL.Query().Get("label")
		pkH.FinishRegister(w, r, s.UserID, label)
	})
	dashMux.HandleFunc("POST /settings/passkeys/delete", func(w http.ResponseWriter, r *http.Request) {
		s := auth.SessionFrom(r.Context())
		if s == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		idStr := r.FormValue("id")
		credID, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		if err := pkH.DeleteCredential(s.UserID, credID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	// Mount the auth-protected mux as a fallback for everything not matched above.
	// We intercept "/" specifically: redirect to /setup if not complete, /login if not authenticated.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		complete, err := settings.IsSetupComplete(d)
		if err != nil {
			logger.Error("read setup state", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !complete {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		// Authenticated dispatch.
		authMW(dashMux).ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	startBackgroundCleanup(ctx, d)

	go func() {
		logger.Info("server starting", "addr", cfg.Listen, "version", version, "commit", commit)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown requested")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
}
