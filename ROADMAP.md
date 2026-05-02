# Roadmap

## v1 (initial release)

- [ ] First-run wizard: admin user, SMTP, Headscale connection.
- [ ] Local user store: username + email + password (Argon2id).
- [ ] TOTP 2FA with QR enrollment + single-use recovery codes.
- [ ] Server-side sessions (SQLite), `HttpOnly` + `SameSite=Lax`, `Secure` when proxied via HTTPS.
- [ ] CSRF protection on all state-changing forms.
- [ ] Login rate limit + account lockout (5 fails / 10 min → 15 min lockout).
- [ ] Audit log (every state change → `audit_log` table).
- [ ] Headscale gRPC client: list/create/delete users, list/expire/rename/delete nodes, manage pre-auth keys, routes/ACLs view.
- [ ] fail2ban filter + jail snippet shipped, journald-driven.
- [ ] systemd unit, NGINX sample, install.sh, GoReleaser linux/amd64+arm64 binaries.
- [ ] Tabler.io theme integration.

## v1.x

- [ ] **WebAuthn / FIDO2 (Yubikey)** — multiple credentials per user, coexists with TOTP. Library: `github.com/go-webauthn/webauthn`. Schema is already designed for this from day one.
- [ ] Passkey login (same library, comes nearly free with WebAuthn).
- [ ] Password reset via SMTP token email.
- [ ] 2FA recovery flow via email.
- [ ] Per-user API tokens for read-only programmatic access.

## v2 (post-foundation)

- [ ] OIDC SSO (likely shared with Headscale's IdP).
- [ ] Audit log export: syslog, JSON file, optional webhook.
- [ ] Multi-admin roles (read-only operator vs full admin).
- [ ] Dark mode.
- [ ] Backup/restore for dashboard state (users, sessions, audit log).

## Explicit non-goals

- Replacing the `headscale` CLI. We use its gRPC API; we do not shell out.
- Direct Headscale DB access. Schema is internal — we never read or write it.
- Acting as a TLS terminator. HAProxy or NGINX in front handles that.
