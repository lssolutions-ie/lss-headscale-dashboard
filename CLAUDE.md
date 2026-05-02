# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A self-hosted web management dashboard for [Headscale](https://github.com/juanfont/headscale). Single Go binary, server-rendered, ships with a one-line installer. Designed to run **co-located with `headscaled`** so it can edit columns the API doesn't expose (ipv4, ipv6, hostname) directly in Headscale's SQLite DB and restart Headscale to pick up the change. Remote installs work too — they just lose the direct-DB features.

## Stack

- **Backend:** Go 1.25+, stdlib `net/http` (Go 1.22+ method-prefixed mux patterns).
- **Templating:** stdlib `html/template` with `embed.FS`.
- **Interactivity:** plain `fetch()` and small inline scripts; HTMX is loaded but only used in a couple of places.
- **UI theme:** [Tabler.io](https://tabler.io) loaded from CDN at runtime (no static-asset bundling).
- **Storage (dashboard):** SQLite via `modernc.org/sqlite` (pure Go, **CGO-free**).
- **Headscale API:** HTTP/REST against `/api/v1/...` over Headscale's gRPC-Gateway, Bearer API key. No protoc / generated stubs.
- **WebAuthn:** `github.com/go-webauthn/webauthn` for passkey/Yubikey registration (login-via-passkey is roadmap).

When adding dependencies, prefer pure-Go packages so `CGO_ENABLED=0` builds keep working.

## Headscale communication

Two channels:

1. **REST API** (always): `internal/headscale/client.go` calls `/api/v1/user`, `/api/v1/node`, `/api/v1/preauthkey`, `/api/v1/policy`, etc. Bearer auth. Configured under Settings → Headscale connection (Address + API key + ClientURL for the public Tailscale-client URL).

2. **Local SQLite + systemctl** (optional, on-host only): `internal/headscaledb` opens Headscale's `db.sqlite` directly to write columns the API doesn't expose (`ipv4`, `ipv6`, `hostname`, plus the rest of the row). After a write, runs the configured restart command (default `sudo -n /usr/bin/systemctl restart headscale.service`) and the wait/spinner page polls `/headscale/ready` until the API answers again.

   Column whitelist in `internal/headscaledb/headscaledb.go` (`AllowedColumns`). Do not pass user-supplied column names to the UPDATE — only entries in that whitelist.

**Hard rules:**

- Never shell out to the `headscale` CLI from request handlers. Use the REST API.
- Direct DB writes go through `headscaledb.UpdateNodeFields` (whitelisted, parameterized) — never construct SQL from form input.
- The Edit Node modal's data is fetched via `headscaledb.ListFullNodes` and passed in as `DBNodes` map[string]FullNode keyed by row id. Each modal renders only the columns we whitelisted.
- The Restart Headscale code path always runs through the configured RestartCmd; if you change the default, update install.sh's sudoers drop-in too.

## Deploy topology

```
Default install (no proxy):
    Internet → :9000 (Go app, 0.0.0.0:9000) → Headscale REST + local DB

Production (HAProxy on the perimeter):
    Internet → HAProxy (TLS) → :9000 (Go app, set to 127.0.0.1) → Headscale
```

- Default `listen` is `0.0.0.0:9000`. Switch to `127.0.0.1:9000` when HAProxy/nginx is in front.
- TLS is HAProxy's job; the Go app speaks plain HTTP.
- Cookies flip `Secure` when `X-Forwarded-Proto: https` is observed.
- WebAuthn registration **requires HTTPS** in browsers (loopback excluded). For passkey use, the dashboard must be reached via HTTPS via HAProxy.

## Co-location with Headscale (installer behavior)

`scripts/install.sh` detects `headscale.service` on the host and, when present:

- Adds the dashboard service user to the `headscale` group (so it can read the SQLite file via group perms).
- Installs `acl` package and applies a default ACL on `/var/lib/headscale` so the user retains rw on Headscale's WAL/SHM files even after Headscale recreates them on restart.
- Drops a sudoers file at `/etc/sudoers.d/lss-headscale-dashboard` granting passwordless `systemctl restart headscale[.service]`.
- Drops `/etc/systemd/system/lss-headscale-dashboard.service.d/headscale-colocation.conf` adding `/var/lib/headscale` to `ReadWritePaths` (the unit otherwise has `ProtectSystem=strict` which would block writes).
- The unit intentionally does **not** set `NoNewPrivileges` because sudo (setuid) needs it off.

## First-run wizard (`/setup`)

Step 1 only at present. Creates the admin user (Argon2id), enrolls TOTP with QR + 10 single-use recovery codes shown once. After confirmation: `setup_complete=true` is written to the dashboard's settings KV table, redirects to `/login`. SMTP and Headscale connection get configured from `/settings` after first login.

## Auth model

- Username/email + password (Argon2id) + TOTP. Recovery codes (`XXXX-XXXX-XXXX` or 12 chars) accepted in lieu of TOTP at login.
- Server-side sessions in SQLite. Cookie carries an opaque session id; logout invalidates the row.
- Schema (`webauthn_credentials` table) supports multiple authenticators per user from day one. Passkey **registration** ships in v1.0+; **login-via-passkey** is roadmap.
- Login rate limit + lockout: 5 fails per 10 min → 15 min lockout (per username+IP).
- CSRF token on every form.

## Audit log

`internal/audit` writes a row per state change: `(ts, actor_user_id, ip, action, target, details_json)`. Logins (success + failure), logout, password change, settings updates, Headscale CRUD, SMTP test, passkey registration, node DB edits all go through here. Audit log is append-only.

## Logging conventions (fail2ban depends on this)

- `slog` text handler (key=value).
- Failed logins **must** log:

  ```go
  slog.Warn("auth: failed login", "user", username, "ip", remoteIP)
  ```

  The fail2ban filter at `deploy/fail2ban/filter.d/lss-headscale-dashboard.conf` matches `level=WARN`, `msg="auth: failed login"`, and captures `ip=<HOST>`. If this log line changes, update the filter regex in the same commit.

## Install / release

- Install: `curl -fsSL https://raw.githubusercontent.com/lssolutions-ie/lss-headscale-dashboard/main/scripts/install.sh | sudo sh`. Optional `LSS_VERSION=vX.Y.Z` and `LSS_PORT=N`.
- Releases: push a tag matching `v*.*.*`. GoReleaser builds linux/amd64 + linux/arm64 tarballs and uploads `install.sh` as a top-level release asset.
- Cross-compile depends on `CGO_ENABLED=0` — don't introduce CGO deps.

## Layout

```
cmd/dashboard/main.go              # entry point + route wiring
internal/
  audit/                           # audit log writer
  auth/                            # password (argon2id), totp, recovery codes,
                                   # sessions, ratelimit + lockout, middleware
  dashboard/                       # authenticated UI (post-login)
    handlers.go                    # nodes / users / preauthkeys / settings / register-node
    policy.go                      # ACL viewer + builder + raw editor
    templates/                     # base.html + per-page html/templates
  db/                              # dashboard's own SQLite + migrations
  headscale/                       # REST client (Users, Nodes, PreAuthKeys, Policy)
  headscaledb/                     # local DB editor (Headscale's SQLite)
  login/                           # /login + /logout + per-form CSRF
  passkey/                         # WebAuthn registration via go-webauthn
  settings/                        # typed KV access (Headscale, HeadscaleDB, SMTP)
  setup/                           # first-run wizard (admin user + TOTP)
  smtp/                            # net/smtp wrapper (none / starttls / implicit-TLS)
  users/                           # admin user creation, TOTP/recovery storage
deploy/
  systemd/, nginx/, fail2ban/      # reference configs (installer applies systemd)
scripts/install.sh                 # one-line installer
.github/workflows/                 # ci.yml + release.yml
.goreleaser.yaml
```

## Dev commands

- `make build` — build to `bin/lss-headscale-dashboard`.
- `make run` — run with `config.example.yaml`.
- `make lint` — `go vet ./...`.
- `make test` — `go test ./...`.
- `make tidy` — `go mod tidy`.

## Things to be careful about

- **`tags` is a SQLite reserved word.** When SELECT-ing from Headscale's `nodes` table, quote it as `"tags"`. UPDATE doesn't need the quotes.
- **Tabler dropdowns inside `.table-responsive`** are clipped by the card's `overflow: hidden`. Use the `.allow-overflow` class on the card and `data-bs-strategy="fixed"` on the toggle.
- **html/template `slice` panics** on out-of-range. Don't write `{{slice .Foo 0 12}}`; use the `{{truncate .Foo 12}}` helper or guard with `{{if ge (len .Foo) 12}}`.
- **Node ID changes** are safe in Headscale 0.28+ (no FK references to nodes.id; routes are stored inline as `approved_routes` text). Always restart Headscale after.
- **Headscale `server_url`** (the URL Tailscale clients use) usually differs from the API URL the dashboard talks to. Stored separately as `Headscale.ClientURL`. Used in the Register Node command.
- **Don't break the fail2ban log format.** If you change the failed-login slog line, update `deploy/fail2ban/filter.d/...conf` in the same change.
- **Don't introduce CGO.** SQLite via `modernc.org/sqlite`. Cross-compile in CI depends on this.
- **Always restart Headscale after a direct-DB write.** The `restart_after` checkbox in the Edit modal handles this; the wait/spinner page (`/nodes/wait`) polls `/headscale/ready` until the API answers.
