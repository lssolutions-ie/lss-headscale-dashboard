# Roadmap

Current release: **v1.13.0** — production daily-driver, 86 nodes in flight.

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

## Shipped (v1.10 → v1.13)

- **Per-OS install one-liners on the Register Node modal** (Linux / macOS /
  Windows / Already installed). Windows variant downloads the NSIS installer,
  stops the service before install so the daemon binary actually gets
  replaced, then registers — fix for the months-long "v1.96 on disk but
  v1.56 in memory" upgrade gotcha (v1.10.4).
- **`--advertise-tags` removed from the generated `tailscale up`** because
  Headscale 0.28's `state.go:1335` rejects any pre-auth-key registration
  whose Hostinfo.RequestTags is non-empty (v1.10.6). Tags travel on the
  auth key's `aclTags` instead. Closes the misleading
  `requested tags [...] are invalid or not permitted` reports that had
  been baffling for hours.
- **Stale-node detection** on `/nodes` — server computes
  `IsStale = last_seen > 30 days OR unparseable`, header badges show
  total / online / offline / stale (mutually exclusive), per-row
  filter chip and a small "stale" pill in the Last seen column. Helps
  spot zombie node rows before they create noise (v1.10.5 → v1.10.8).
- **DERP column** on `/nodes` and on the per-node detail page, parsed
  from `host_info.NetInfo.PreferredDERP`. Region 999 → "LSS" by name,
  Tailscale's public fleet's typical city codes as best-effort
  fallback. Filter chip lists regions actually in use plus
  "No DERP" (v1.12.0).
- **Saved Register-Node presets** — top-of-modal preset chooser plus a
  "Save as preset" button next to Generate. Stored in dashboard
  SQLite as a JSON values map so the schema doesn't churn when the
  form gains flags (v1.11.0). Subtle JS gotcha that bit us: the form
  has `<input name="reset">`, which shadows `HTMLFormElement.reset()`
  via named-accessor — fixed in v1.11.1 by walking the field list
  explicitly instead of calling `.reset()`.
- **Filter persistence** across page renders. Every `data-search` /
  `data-filter` / `data-attr-filter` value is keyed into
  sessionStorage and re-applied on the next paint, so filtering by tag
  and then editing a node (which round-trips through `/nodes/wait`)
  no longer drops you back on an unfiltered table (v1.11.2).
- **Per-node detail page at `/nodes/{id}`** — header with
  status/stale/DERP badges, identity / network / tags / auth-key
  cards, full pretty-printed `host_info`, recent audit events
  filtered to the node, read-only crypto-keys card, and the Edit
  modal embedded so editing doesn't bounce back to the index
  (v1.13.0). The `given_name` in the index table now links here.
- **Embedded Headscale DERP wired into the production stack** —
  documented config knobs (custom STUN port to coexist with Unifi's
  3478, public IPv4 of the HAProxy front, `timeout tunnel 1h` on
  HAProxy's headscale backend so DERP WebSockets don't get torn
  down). Region 999 = "LSS" baked into the dashboard's name lookup.
- **UI polish:** white text on `bg-warning` badges, "Choose owner
  user" placeholder in the Register Node form (no more
  alphabetically-first-wins gotcha), emoji icons dropped from OS
  tabs, dropdown defaulting fixed (v1.11.1).
- **Documented Headscale 0.28 quirks** that aren't fixable from the
  dashboard side — auth-key parser shape (88 chars exactly), hostname
  auto-revert race, stale-node-row registration interference. All in
  the per-session memory under
  `~/.claude/projects/.../memory/`.

## On the radar (not started)

- [ ] **Bulk node operations** — checkbox per row, "Delete selected" /
  "Edit tags on selected", with one Headscale restart at the end
  instead of per-row. The 37-stale-node cleanup pain motivates this.
- [ ] **Sticky hostname/given_name edits** — when the dashboard writes
  `nodes.hostname`, also rewrite the embedded `host_info.Hostname`
  field so Headscale's `hostinfoChanged` diff returns false on the
  next MapRequest and `ApplyHostnameFromHostInfo` doesn't clobber
  the change. Closes a documented race (see
  `reference_hostname_autosync.md` in memory).
- [ ] **SMTP alerts** layered on the existing audit writes —
  failed-login bursts, Headscale restart-via-dashboard, node going
  stale past a configurable threshold, fresh pre-auth key created.
  Configurable per event class.
- [ ] **DNS / MagicDNS settings panel** — Headscale's DNS is config-
  file-driven (no API), but the dashboard already edits
  `/etc/headscale/config.yaml` for HeadscaleDB; same path here.
- [ ] **Auto-prune stale nodes** — opt-in setting "delete nodes
  unseen >N days, nightly", audit-logged, off by default. Closes
  the loop the stale filter opened.
- [ ] **Routes page approve/disable controls** — today route changes
  go through the Edit Node modal's `approved_routes` field; per-row
  Approve / Disable + bulk approve.
- [ ] **NetInfo surfaced cleanly on `/nodes/{id}`** — NAT type,
  WorkingUDP, UPnP/PMP/PCP flags, MappingVariesByDestIP. Currently
  buried in the JSON blob.
- [ ] **Copy-to-clipboard** on the long key fields (machine_key,
  node_key, disco_key) of the detail page.

## Deferred (real, not blocking)

- [ ] **Per-user API tokens** for read-only programmatic access (no
  use case yet on a single-admin install)
- [ ] **Multi-admin roles** (read-only operator vs full admin) — same
- [ ] **OIDC SSO** (likely shared with Headscale's IdP)
- [ ] **Audit log syslog / webhook export** (JSON download exists; a
  streaming export to syslog or webhook would help long-term
  retention)
- [ ] **Backup/restore for dashboard state** (we proved the manual
  procedure in the v1.9 audit; a UI button would make it routine)
- [ ] **Dark mode**

## Explicit non-goals

- Replacing the `headscale` CLI. We use its REST API; we don't shell
  out from request handlers.
- Acting as a TLS terminator. HAProxy in front handles that.
- Running a derper binary from the dashboard process. Operators run
  Headscale's embedded DERP (or a separate `derper`); the dashboard
  only surfaces what region each node prefers.
