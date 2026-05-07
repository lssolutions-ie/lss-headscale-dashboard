# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A self-hosted web management dashboard for [Headscale](https://github.com/juanfont/headscale). Single Go binary, server-rendered, ships with a one-line installer. Designed to run **co-located with `headscaled`** so it can edit columns the API doesn't expose (ipv4, ipv6, hostname, machine_key, etc.) directly in Headscale's SQLite DB and restart Headscale to pick up the change. Remote installs work too — they just lose the direct-DB features.

Current release: **v1.9.0**. Considered feature-complete for daily-driver use. See ROADMAP.md for the items deferred to v1.10+.

## Stack

- **Backend:** Go 1.25+, stdlib `net/http` (Go 1.22+ method-prefixed mux patterns).
- **Templating:** stdlib `html/template` with `embed.FS`. Each page renders via the dashboard's per-request `Clone() + ParseFS` pattern so `content`/`title` blocks don't collide across files.
- **UI theme:** [Tabler.io](https://tabler.io) 1.0.0-beta20 — **vendored** under `internal/web/static/tabler/`, served at `/static/...`. No CDN at runtime.
- **Storage (dashboard's own DB):** SQLite via `modernc.org/sqlite` (pure Go, **CGO-free**).
- **Headscale API:** HTTP/REST against `/api/v1/...` over Headscale's gRPC-Gateway, Bearer API key. No protoc / generated stubs.
- **WebAuthn:** `github.com/go-webauthn/webauthn` for passkey/Yubikey registration **and** sign-in (Bitwarden tested).

When adding dependencies, prefer pure-Go packages so `CGO_ENABLED=0` builds keep working.

## Headscale communication

Two channels:

1. **REST API** (always): `internal/headscale/client.go` calls `/api/v1/user`, `/api/v1/node`, `/api/v1/preauthkey`, `/api/v1/policy`. Bearer auth. Configured under Settings → Headscale connection.

2. **Local SQLite + systemctl** (optional, on-host only): `internal/headscaledb` opens Headscale's `db.sqlite` directly to write columns the API doesn't expose. After a write, runs the configured restart command (default `sudo -n /usr/bin/systemctl restart headscale.service`); `/nodes/wait` page polls `/headscale/ready` until the API answers again.

   Column whitelist in `internal/headscaledb/headscaledb.go`. Two tiers:

   - **`SafeColumns`** — id, hostname, given_name, ipv4, ipv6, tags, approved_routes, register_method, auth_key_id, endpoints, host_info, last_seen, expiry, created_at, updated_at, deleted_at.
   - **`DangerColumns`** — machine_key, node_key, disco_key, user_id. Edit Node modal requires an explicit "Enable dangerous edits" checkbox; the handler skips danger columns when it isn't ticked and reports them in the flash.

**Hard rules:**

- Never shell out to the `headscale` CLI from request handlers. Use the REST API.
- Direct DB writes go through `headscaledb.UpdateNodeFields` (whitelisted, parameterized) — never construct SQL from form input.
- The Restart Headscale code path always runs through the configured `RestartCmd`; if you change the default, update `install.sh`'s sudoers drop-in too.

## Headscale 0.28 quirks worth knowing

- **Pre-auth key expire silently no-ops over the API.** The endpoint matches by full key value but Headscale only persists `prefix + hash` for newer keys, so the value is gone after the create response. We use `headscaledb.ExpirePreAuthKeyByID` (direct UPDATE) instead. Don't reach for `c.ExpirePreAuthKey` — it's removed. `c.CreatePreAuthKey` and `c.ExpirePreAuthKey` (when you re-add it) need the *numeric* user_id, not name; use `userIDByName`.
- **`tags` is the merged field** — Headscale 0.28's API exposes only the combined tag list, not the forced/valid/invalid split.
- **`pre_auth_keys.id` is FK-referenced from `nodes.auth_key_id`** with no `ON DELETE`. Deleting a key with referencing nodes crashes Headscale on next start (status=216/GROUP-style failure). `headscaledb.DeletePreAuthKey` refuses such deletes; the dashboard UI doesn't expose Delete at all (only Expire, by ID, via direct DB).
- **Routes are stored inline** as `nodes.approved_routes` JSON column — there's no separate routes table.
- **Headscale's API returns user IDs as strings** even though they're uint64 in the proto.
- **Usernames must contain `@`** for Headscale 0.28's ACL v2 parser. Any policy whose `groups` references a non-`@` user gets rejected with `"Username has to contain @"`. The `/users` New-user form requires `@` up-front; rename existing users with `headscale users rename --identifier <numeric-id> --new-name <name@suffix>` (the `--name` flag won't match a bare username because the lookup itself expects `@`).
- **Check the `*` Tabler badge text colour** — Tabler's `bg-success`/`bg-danger` rules beat `.text-white`. Use `!important` overrides (already in `base.html`).

## Deploy topology

```
Default install (no proxy):
    Internet → :9000 (Go app, 0.0.0.0:9000) → Headscale REST + local DB

Production (HAProxy on the perimeter):
    Internet → HAProxy (TLS) → :9000 (Go app, set to 127.0.0.1) → Headscale
```

- Default `listen` is `0.0.0.0:9000`. Switch to `127.0.0.1:9000` when HAProxy/nginx is in front.
- TLS is HAProxy's job; the Go app speaks plain HTTP.
- WebAuthn requires HTTPS in browsers (loopback excepted). On non-secure contexts the passkey buttons disable themselves with an explanation.
- The dashboard's WebAuthn `rpFromRequest` defaults to `https` for any non-loopback host so it works behind HAProxy even if `X-Forwarded-Proto` isn't passed.

## Co-location with Headscale (installer behavior)

`scripts/install.sh` detects `headscale.service` on the host and, when present:

- Adds the dashboard service user to the `headscale` group.
- Installs `acl` package and applies a default ACL on `/var/lib/headscale` so the user retains rw on Headscale's WAL/SHM files even after Headscale recreates them on restart.
- Drops a sudoers file at `/etc/sudoers.d/lss-headscale-dashboard` granting passwordless `systemctl restart headscale[.service]`.
- Drops `/etc/systemd/system/lss-headscale-dashboard.service.d/headscale-colocation.conf` adding `/var/lib/headscale` to `ReadWritePaths` (the unit otherwise has `ProtectSystem=strict` which would block writes).
- The unit intentionally does **not** set `NoNewPrivileges` because sudo (setuid) needs it off.

## First-run wizard (`/setup`)

Three steps:

1. **`/setup`** — admin user (Argon2id) + TOTP enrollment with QR + 10 single-use recovery codes shown once.
2. **`/setup/smtp`** — SMTP host/port/from/user/pass/TLS. Skippable (sets `smtp.enabled=false`).
3. **`/setup/headscale`** — address + API key + ClientURL + tls_skip. "Test & finish" calls `headscale.TestConnection` before persisting; "Skip" finishes setup with no Headscale config.

`setup_complete=true` is written to the settings KV table only at the **end** of step 3 (or when Skip is chosen). All wizard routes are wrapped in `guardSetup` middleware that redirects to `/login` once the flag is set.

## Auth model

- Username/email + password (Argon2id) + TOTP. Recovery codes (`XXXX-XXXX-XXXX` or 12 chars) accepted in lieu of TOTP at login.
- WebAuthn / passkey sign-in (Bitwarden, Yubikey, Touch ID, Windows Hello) — registration via `/settings#passkeys`, sign-in button on `/login`. Credential stores include `BackupEligible` / `BackupState` to keep go-webauthn's strict consistency check happy.
- Server-side sessions in SQLite. Cookie carries an opaque session id; logout invalidates the row.
- Password reset via SMTP — `/forgot` sends a one-time SHA-256-hashed token (1h TTL) to the email on file; `/reset/{token}` validates and rotates the password, **invalidating every existing session for that user**.
- Login rate limit + lockout: 5 fails per 10 min → 15 min lockout (per username+IP).
- CSRF: a single helper in `internal/auth/csrf.go` (`EnsureCSRFToken` / `CheckCSRFToken`) used by login, setup, and dashboard. Cookie lifetime = session lifetime; refreshes on every render.

## Audit log

`internal/audit` writes a row per state change. Logins (success + failure), logout, password change/reset, settings updates, Headscale CRUD, SMTP test, passkey registration, node DB edits, tag rename/delete, policy edits, pre-auth-key expire all go through here.

`Write` swallows nothing — DB errors are surfaced to `slog.Error`. Audit log is append-only; the `/audit` page paginates the latest 200 rows. `/audit/export.json` streams up to 50k rows as a JSON array download.

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
- Static assets are vendored under `internal/web/static/` so the binary is self-contained (~23 MB, was 15 MB before vendoring).

## Layout

```
cmd/dashboard/main.go              # entry point + route wiring
internal/
  audit/                           # audit log writer (errors surface to slog)
  auth/                            # password (argon2id), totp, recovery codes,
                                   # sessions, ratelimit, middleware, CSRF, ClientIP,
                                   # SetupSigner (HMAC key persisted in settings)
  dashboard/                       # authenticated UI (post-login)
    handlers.go                    # nodes / users / preauthkeys / settings /
                                   # register-node / audit / routes / safe-danger
    policy.go                      # ACL viewer + builder + raw editor
    tags.go                        # /tags page (rename/delete with full propagation)
    templates/                     # base.html + per-page html/templates
  db/                              # dashboard's own SQLite + migrations
  headscale/                       # REST client (Users, Nodes, PreAuthKeys, Policy)
  headscaledb/                     # local DB editor (Headscale's SQLite); SafeColumns + DangerColumns
  login/                           # /login + /logout + /forgot + /reset/{token}
  passkey/                         # WebAuthn registration + sign-in
  settings/                        # typed KV access (Headscale, HeadscaleDB, SMTP)
  setup/                           # first-run wizard (3 steps, guardSetup middleware)
  smtp/                            # net/smtp wrapper (none / starttls / implicit-TLS)
  users/                           # admin user creation, TOTP/recovery storage
  web/                             # //go:embed Tabler + HTMX dist; /static/* handler
deploy/
  systemd/, nginx/, fail2ban/      # reference configs (installer applies systemd)
scripts/install.sh                 # one-line installer
.github/workflows/                 # ci.yml + release.yml
.goreleaser.yaml
```

## Routes

```
Public:
  GET  /healthz
  GET  /static/...                  (Tabler + HTMX, vendored)
  GET  /login
  POST /login
  POST /logout                      (CSRF; GET removed)
  GET  /forgot,  POST /forgot
  GET  /reset/{token},  POST /reset/{token}
  POST /login/passkey/begin
  POST /login/passkey/finish
  GET  /setup,           POST /setup
  POST /setup/totp
  GET  /setup/smtp,      POST /setup/smtp
  GET  /setup/headscale, POST /setup/headscale
  GET  /setup/done
  POST /setup/test-headscale

Authenticated:
  GET  /                            (overview)
  GET  /users,        POST /users/{create,delete}
  GET  /nodes,        POST /nodes/{expire,delete,tags,edit,register}
  GET  /nodes/wait                  (post-restart spinner)
  GET  /preauthkeys,  POST /preauthkeys/{create,expire}
  GET  /tags,         POST /tags/{add,rename,delete}
  GET  /routes
  GET  /policy,       POST /policy
  POST /policy/{rules,groups,tagowners}/add
  GET  /audit,        GET /audit/export.json
  GET  /settings,     POST /settings/{headscale,headscale/test,headscale-db,headscale-db/test,smtp,smtp/test,password}
  POST /headscale/restart
  GET  /headscale/ready
  POST /settings/passkeys/{register/begin,register/finish,delete}
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
- **html/template `slice` panics** on out-of-range. Use the `{{truncate .Foo 12}}` helper or guard with `{{if ge (len .Foo) 12}}`.
- **Node ID changes are safe** in Headscale 0.28+ (no FK references to nodes.id; routes are stored inline as `approved_routes` text). Always restart Headscale after.
- **Headscale `server_url`** (the URL Tailscale clients use) usually differs from the API URL the dashboard talks to. Stored separately as `Headscale.ClientURL`. Used in the Register Node command and forms an `href` from the dashboard's own host header in WebAuthn RP origin.
- **WebAuthn requires HTTPS** in browsers (loopback excepted). Both Register and Sign-in buttons disable themselves up-front when `navigator.credentials` or `window.isSecureContext` is unavailable.
- **Don't break the fail2ban log format.** If you change the failed-login slog line, update `deploy/fail2ban/filter.d/...conf` in the same change.
- **Don't introduce CGO.** SQLite via `modernc.org/sqlite`. Cross-compile in CI depends on this.
- **Always restart Headscale after a direct-DB write.** The `restart_after` checkbox in the Edit modal handles this; the wait/spinner page (`/nodes/wait`) polls `/headscale/ready` until the API answers. Polling timeout is 90s — busy NetMap rebuilds (many nodes) can take ~minute.
- **Password reset deliberately doesn't reveal user existence.** `/forgot` always renders the success page; failures are logged to slog only. Keep it that way.
