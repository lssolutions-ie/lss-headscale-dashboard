# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A self-hosted web management dashboard for [Headscale](https://github.com/juanfont/headscale). Single Go binary, server-rendered, ships with a one-line installer. The dashboard typically lives **on the same host as `headscaled`** and talks to it over its local gRPC unix socket, but the first-run wizard also supports pointing at a remote Headscale instance over gRPC + TLS.

## Stack

- **Backend:** Go 1.25+, stdlib `net/http` (Go 1.22+ method-prefixed mux patterns; can graduate to `chi` if routing complexity warrants it). Logging via `log/slog`.
- **Templating:** stdlib `html/template` with `embed.FS` (no codegen step). [templ](https://templ.guide) is a future option if templating gets complex; not used for v1.
- **Interactivity:** [HTMX](https://htmx.org) — no Node toolchain, no SPA.
- **UI theme:** [Tabler.io](https://tabler.io) prebuilt CSS/JS, dropped into `static/tabler/` (gitignored — fetched at install time, see README).
- **Storage:** SQLite via `modernc.org/sqlite` (pure Go, **CGO-free** — keeps cross-compile in CI trivial).
- **gRPC:** `google.golang.org/grpc` + generated stubs from vendored Headscale `.proto` files.

When adding dependencies, prefer pure-Go packages so `CGO_ENABLED=0` builds keep working.

## Headscale communication

gRPC. Two modes, picked by the user in the setup wizard and persisted in `config.yaml`:

- `socket` (default, on-host install): `unix:///var/run/headscale/headscale.sock`. The systemd unit sets `SupplementaryGroups=headscale` so the service user can read it.
- `grpc` (remote install): `host:port` + `tls: true` + Bearer API key in gRPC metadata.

**Current state (v1.0.0):** `internal/headscale/client.go` calls Headscale's gRPC-Gateway HTTP/REST API at `/api/v1/...` with a Bearer API key. This avoids the protoc + Go-stub generation that raw gRPC would require, while covering every management endpoint. Address + API key are configured via the dashboard's Settings page (or wizard step 3 once it's built).

**Hard rules:**

- Never read Headscale's database directly. Schema is internal.
- Never shell out to the `headscale` CLI. Use the gRPC API.
- Always test the connection in the setup wizard (e.g. `ListNodes`) before persisting Headscale config — saving an unreachable config bricks the dashboard.

## Deploy topology

```
Default install (no proxy on the host):
    Internet → :9000 (Go app, 0.0.0.0:9000) → Headscale gRPC

Production (HAProxy on the perimeter):
    Internet → HAProxy (TLS) → :9000 (Go app, set to 127.0.0.1) → Headscale gRPC
```

- Default `listen` is `0.0.0.0:9000` so the installer's `curl|sh` produces a directly-reachable dashboard. When HAProxy/nginx is added on the same host, change `listen` in `config.yaml` to `127.0.0.1:9000` so the dashboard is only reachable via the proxy. `deploy/nginx/lss-headscale-dashboard.conf` is reference config for that scenario; the installer does not enable it.
- TLS, HSTS, HTTP→HTTPS redirect: HAProxy's job. The Go app does not handle TLS at all.
- Trust `X-Forwarded-Proto` and `X-Forwarded-For` only when the connection's remote address matches a CIDR in `trust_proxy` (configured; loopback only by default).
- Session cookies: `HttpOnly` and `SameSite=Lax` always. `Secure` when the request was forwarded over HTTPS (`X-Forwarded-Proto: https`).

## First-run wizard (`/setup`)

On boot the app reads `setup_complete` from config (and/or a flag row in SQLite). If false, all routes except `/setup`, `/healthz`, and `/static/*` redirect to `/setup`. Three steps:

1. **Admin user** — username, email, password (Argon2id), forced TOTP enrollment with QR + recovery codes shown once. Must be saved before continuing.
2. **SMTP** — host, port, username, password, from-address, TLS mode (`none` / `starttls` / `tls`). "Send test email" button. **Skippable** with a warning that password reset and 2FA recovery emails will not work; can be revisited later under `/admin/settings`.
3. **Headscale connection** — `socket` (default) or `grpc` (remote). "Test connection" button must succeed before submit is enabled.

On finish: write `config.yaml` (non-secret) + `secrets.yaml` (mode 0600, contains API key, SMTP password, session signing key), set `setup_complete=true`, redirect to `/login`.

## Auth model

- v1: username + email + password (Argon2id) + TOTP 2FA + single-use recovery codes.
- Sessions: server-side store in SQLite. Cookie carries an opaque session id, never a JWT. Logout invalidates the row.
- **Schema is designed to support multiple authenticators per user from day one** — adding WebAuthn/Yubikey later is additive, not a migration. See ROADMAP.md.
- Login rate limit + lockout: defaults `5 attempts / 10 min` → `15 min lockout`. Configurable under `auth:` in config.
- CSRF: on all state-changing forms.

## Audit log

Every state change writes a row to `audit_log`: `(ts, actor_user_id, ip, action, target, details_json)`. Examples of `action`: `user.create`, `user.delete`, `node.expire`, `preauthkey.create`, `settings.update`. Read-only views do not write to the audit log. The audit log is append-only — never edit existing rows.

## Logging conventions (IMPORTANT — fail2ban depends on this)

- Use `slog.Default()` with a **text** handler (key=value pairs).
- Failed logins **must** log:

  ```go
  slog.Warn("auth: failed login", "user", username, "ip", remoteIP)
  ```

  The fail2ban filter at `deploy/fail2ban/filter.d/lss-headscale-dashboard.conf` matches `level=WARN`, `msg="auth: failed login"`, and captures `ip=<HOST>`. **If you change this log call, update the filter in the same commit.**
- The default backend in `deploy/fail2ban/jail.d/` is `systemd` with `journalmatch=_SYSTEMD_UNIT=lss-headscale-dashboard.service`, so logs must go to stdout/stderr (which systemd journals automatically). Do not write to a separate logfile by default.

## Install / release

- One-line install: `curl -fsSL https://raw.githubusercontent.com/lssolutions-ie/lss-headscale-dashboard/main/scripts/install.sh | sudo sh`. Once a release exists, the install script also accepts `LSS_VERSION=vX.Y.Z`.
- Releases are cut by pushing a tag matching `v*.*.*`. GoReleaser builds linux/amd64 + linux/arm64 tarballs containing the binary, configs, and deploy artifacts. The install script is also uploaded as a top-level release asset.
- Cross-compilation depends on **CGO_ENABLED=0** — do not introduce CGO dependencies.

## Layout (target)

```
cmd/dashboard/             # main.go entry point (exists)
internal/
  config/                  # config.yaml load + env override
  server/                  # router, middleware (csrf, session, ratelimit, audit, proxy-headers)
  auth/                    # password (argon2id), totp, sessions, recovery codes
  headscale/               # gRPC client wrapper
    proto/                 # vendored upstream .proto + generated *.pb.go
  setup/                   # first-run wizard handlers
  audit/                   # audit log writer
  views/                   # templ components (Tabler-themed)
  db/                      # SQLite open + migrations
deploy/
  systemd/                 # service unit (exists)
  nginx/                   # site sample (exists)
  fail2ban/                # filter + jail (exists)
scripts/install.sh         # one-line installer (exists)
static/                    # Tabler.io dist (gitignored)
.github/workflows/         # ci.yml + release.yml (exists)
.goreleaser.yaml           # release config (exists)
```

Most `internal/*` packages are not yet implemented — the scaffold currently has only `cmd/dashboard/main.go` with stub `/healthz` and `/setup` handlers. Build them as the work needs them; do not pre-create empty packages.

## Dev commands

- `make build` — build to `bin/lss-headscale-dashboard`.
- `make run` — run with `config.example.yaml`.
- `make lint` — `go vet ./...`.
- `make test` — `go test ./...`.
- `make tidy` — `go mod tidy`.
- `make proto` — once Headscale gRPC stubs are added (requires `protoc`).

## Things to be careful about

- **Bind matches the deployment.** Default is `0.0.0.0:9000` (turnkey installer). When HAProxy/nginx is in front on the same host, switch `listen` to `127.0.0.1:9000` so the dashboard is only reachable via the proxy.
- **Don't break the fail2ban log format.** If you change the failed-login log call, update `deploy/fail2ban/filter.d/lss-headscale-dashboard.conf` in the same change.
- **Don't bypass the Headscale connection test** in the setup wizard. Saving an unreachable config bricks the dashboard.
- **Don't commit secrets.** API keys, SMTP passwords, and session signing keys live in `secrets.yaml` (mode 0600), written at runtime by the wizard. `config.yaml` and `secrets.yaml` are both gitignored.
- **Don't introduce CGO.** SQLite via `modernc.org/sqlite`, no `mattn/go-sqlite3`. Cross-compile in CI depends on this.
- **Don't pre-create empty packages.** Add `internal/*` directories only when they hold real code.
