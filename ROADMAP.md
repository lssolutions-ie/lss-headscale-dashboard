# Roadmap

Current release: **v1.5.4**.

## Shipped (v1.0 → v1.5)

- First-run wizard step 1 (admin + TOTP + recovery codes)
- Login + sessions + rate-limit + lockout + CSRF + audit log
- Headscale REST client: Users, Nodes, PreAuthKeys, Policy
- Edit Node modal — every column of the `nodes` row editable, organized into
  Identity / Network / Tags & routes / User & auth / Crypto keys (collapsed) /
  Timestamps / host_info
- Direct SQLite editor (`internal/headscaledb`) with column whitelist + sudoers
  + ACL setup + ReadWritePaths drop-in handled by `install.sh`
- Wait/spinner page that polls `/headscale/ready` after a Headscale restart
- ACL Policy page — Builder (chip-based selectors built from existing groups /
  tags / users / hosts / `*`), Structured view, Raw HuJSON editor with
  edits-preserving error handling
- Pre-auth keys: tristate state column (active / expired / used), search +
  state + user filters, ACL-tag input on key creation
- Register Node modal — generates a `tailscale up` command with full flag
  coverage (Network / Auth & state / Access / Linux subnet-router), tag chips
  pulled from `tagOwners`, datetime picker for key expiration with
  +1h/+24h/+7d/+30d/Never presets
- Settings: Headscale connection (incl. ClientURL for the public Tailscale
  URL), Local Headscale DB, SMTP, change password, passkey management
- WebAuthn (passkey) **registration** — login-via-passkey is below
- Tabler.io theme, search box on every table, compact rows, dropdown escape
  via `.allow-overflow` + `data-bs-strategy="fixed"`
- Install: turnkey curl|sh, idempotent re-runs, fail2ban filter, GoReleaser
  linux/amd64+arm64, automatic upgrade flow

## Up next

- [ ] **Wizard step 2 + 3** — currently both happen post-login from `/settings`.
      Consider folding them into the wizard so a fresh install lands on a
      configured dashboard immediately.
- [ ] **WebAuthn login flow** — registration works; let users sign in with a
      registered passkey instead of TOTP.
- [ ] **Password reset via SMTP** — depends on SMTP being configured.
- [ ] **Track which auth_key_id registered which node** so a future "Register
      Node" can apply a desired post-registration ID/name automatically once
      the node connects.
- [ ] **Routes / DNS view** — Headscale exposes both via API; dashboard could
      surface them similarly to Nodes.
- [ ] **Per-user API tokens** for read-only programmatic access.
- [ ] **Force re-login after password change.**

## Observability / hardening

- [ ] Move HTMX + Tabler from CDN to vendored static (so the dashboard works
      on hosts without internet egress).
- [ ] Audit log export (syslog / JSON file / webhook).
- [ ] Multi-admin roles (read-only operator vs full admin).
- [ ] Backup/restore for dashboard state.

## Explicit non-goals

- Replacing the `headscale` CLI. We use its REST API; we don't shell out from
  request handlers.
- Acting as a TLS terminator. HAProxy in front handles that.
