# Roadmap

Current release: **v1.9.0** — feature-complete for daily-driver use.

## Shipped (v1.0 → v1.9)

- First-run wizard, all three steps: admin + TOTP, SMTP, Headscale connection
- Login + sessions + rate-limit + lockout + CSRF + audit log (with JSON export)
- Headscale REST client: Users, Nodes, PreAuthKeys, Policy
- Edit Node modal — every column editable, with explicit safe / danger split
- Direct SQLite editor (`internal/headscaledb`) with column whitelist + sudoers
  + ACL setup + ReadWritePaths drop-in handled by `install.sh`
- Wait/spinner page that polls `/headscale/ready` after a Headscale restart
- ACL Policy page — Builder (chip selectors), Structured view, Raw HuJSON
- Tags page — rename / delete with policy + DB propagation across nodes & keys
- Routes page (read-only aggregation)
- Pre-auth keys: tristate state column, search + filters, expire via direct DB
  (API silently no-ops on prefix-only keys)
- Register Node modal — `tailscale up` command builder with full flag coverage,
  ACL-tag chips from `tagOwners`, datetime picker for key expiration
- Settings: Headscale connection (incl. ClientURL), Local Headscale DB, SMTP,
  change password, passkey management
- WebAuthn registration **and** sign-in (Bitwarden, Yubikey, Touch ID, etc.) —
  `BackupEligible`/`BackupState` persisted; in-memory pending sessions swept
- Password reset via SMTP — token-based, 1h TTL, invalidates all sessions
- Tabler.io theme **vendored** (`internal/web/static/`) — works without internet
- HAProxy/loopback-aware: trusts X-Forwarded-Proto/-For; cookies flip Secure
  when proxied via HTTPS; WebAuthn RP origin defaults to https for non-loopback
- fail2ban filter shipped, journald-driven; logs match the filter regex
- systemd unit, install.sh (turnkey on Ubuntu), GoReleaser linux/amd64+arm64
- v1.8 audit pass: setup wizard guard, open-redirect fix, CSRF helpers
  consolidated in `auth/`, audit-write errors surface, persisted setup HMAC key

## Deferred to v1.10+

These are real-but-not-blocking; defer reasons in parens.

- [ ] **Routes page approve/disable controls** (today route changes go through
  the Edit Node modal's `approved_routes` field; a per-row Approve / Disable
  control + bulk approve would be nice)
- [ ] **DNS settings page** (Headscale's DNS is config-file-driven, no API
  surface — would need a separate config-editing flow)
- [ ] **Per-user API tokens** for read-only programmatic access (no use case
  yet on a single-admin install)
- [ ] **Multi-admin roles** (read-only operator vs full admin) — same
- [ ] **OIDC SSO** (likely shared with Headscale's IdP)
- [ ] **Audit log syslog / webhook export** (JSON download exists; a streaming
  export to syslog or webhook would help long-term retention)
- [ ] **Backup/restore for dashboard state** (we proved the manual procedure
  in the v1.9 audit; a UI button would make it routine)
- [ ] **Dark mode**

## Explicit non-goals

- Replacing the `headscale` CLI. We use its REST API; we don't shell out from
  request handlers.
- Acting as a TLS terminator. HAProxy in front handles that.
