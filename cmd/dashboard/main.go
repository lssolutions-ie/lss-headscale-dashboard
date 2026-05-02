package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/auth"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/db"
	"github.com/lssolutions-ie/lss-headscale-dashboard/internal/setup"
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
		Listen:   "127.0.0.1:9000",
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

	signer, err := auth.NewSetupSigner()
	if err != nil {
		logger.Error("setup signer", "err", err)
		os.Exit(1)
	}
	setupH, err := setup.New(d, signer, logger)
	if err != nil {
		logger.Error("setup handler", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	setupH.Routes(mux)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		complete, err := setup.IsComplete(d)
		if err != nil {
			logger.Error("read setup state", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !complete {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		// Post-setup landing — login screen + dashboard land in upcoming releases.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8">
<title>LSS Headscale Dashboard</title>
<body style="font-family:system-ui;max-width:540px;margin:3rem auto;padding:0 1rem;line-height:1.5">
<h1>LSS Headscale Dashboard</h1>
<p>Setup complete. Login screen and dashboard arrive in the next release.</p>
</body>`))
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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
