# Roadmap

## v1.0.0 (shipped)

- [x] First-run wizard (admin user + TOTP + recovery codes)
- [x] Login flow with username/email + password (Argon2id) + TOTP, recovery codes accepted in lieu of TOTP
- [x] Server-side sessions in SQLite (HttpOnly + SameSite=Lax + Secure when behind HTTPS)
- [x] Login rate limit + lockout (5 fails / 10 min → 15 min)
- [x] CSRF protection on every form
- [x] Audit log writes for every state change (logins, settings, Headscale CRUD)
- [x] Audit log viewer in UI
- [x] Headscale REST client (HTTP/gRPC-Gateway): list/create/delete users, list/expire/delete/rename nodes, list/create/expire pre-auth keys
- [x] Settings page: Headscale connection (with test button), SMTP (with send-test button), change password, manage passkeys
- [x] WebAuthn / Yubikey registration + management (login flow via passkey lands in v1.1)
- [x] Tabler.io theme (loaded from CDN)
- [x] HAProxy/loopback-aware: trusts X-Forwarded-Proto/-For; cookies flip Secure when proxied via HTTPS
- [x] fail2ban filter shipped, journald-driven; logs match the filter regex
- [x] systemd unit, install.sh (turnkey on Ubuntu), GoReleaser linux/amd64+arm64

## v1.1 (next)

- [ ] WebAuthn / Yubikey login flow (registration already works; consume credentials at /login)
- [ ] Password reset via SMTP token email
- [ ] 2FA recovery flow via email
- [ ] Per-user API tokens for read-only programmatic access
- [ ] Routes / ACLs view from Headscale (read-only initially)
- [ ] Force re-login on password change

## v2 (post-foundation)

- [ ] OIDC SSO (likely shared with Headscale's IdP)
- [ ] Audit log export: syslog, JSON file, optional webhook
- [ ] Multi-admin roles (read-only operator vs full admin)
- [ ] Dark mode
- [ ] Backup/restore for dashboard state (users, sessions, audit log)

## Explicit non-goals

- Replacing the `headscale` CLI. We use its HTTP API; we do not shell out.
- Direct Headscale DB access. Schema is internal — we never read or write it.
- Acting as a TLS terminator. HAProxy or NGINX in front handles that.
