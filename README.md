# LSS Headscale Dashboard

A self-hosted web management dashboard for [Headscale](https://github.com/juanfont/headscale).
Single Go binary, server-rendered with [templ](https://templ.guide) + [HTMX](https://htmx.org), themed with [Tabler.io](https://tabler.io).

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/lssolutions-ie/lss-headscale-dashboard/main/scripts/install.sh | sudo sh
```

The installer:

- creates a `lss-dashboard` system user (added to the `headscale` group if present)
- installs the binary to `/usr/local/bin/lss-headscale-dashboard`
- writes a systemd unit and starts the service
- installs the fail2ban filter (if `fail2ban-client` is detected)
- prints the URL to the first-run wizard

Then open <http://127.0.0.1:9000/setup> on the host (or via SSH tunnel) and walk through:

1. **Admin user** — username, email, password, TOTP enrollment, recovery codes.
2. **SMTP** — for password reset + 2FA recovery (skippable).
3. **Headscale connection** — local Unix socket (default) or remote gRPC + API key.

## Topology

The default install binds the dashboard to `0.0.0.0:9000`, so it's directly reachable at `http://<server-ip>:9000` once the installer finishes. When you're ready to put HAProxy in front for TLS:

```
Internet → HAProxy (TLS) → :9000 (Go app, switch to 127.0.0.1:9000) → Headscale gRPC
```

Change `listen` in `/etc/lss-headscale-dashboard/config.yaml` to `127.0.0.1:9000` and restart the service. Sample nginx and systemd configs live under `deploy/`.

## Tabler.io assets

The release tarball does not bundle Tabler. Fetch the dist into `static/tabler/`:

```sh
curl -fsSL https://github.com/tabler/tabler/releases/latest/download/tabler.zip \
  -o /tmp/tabler.zip
unzip /tmp/tabler.zip -d /var/lib/lss-headscale-dashboard/static/
```

Or commit your own pinned copy in `static/tabler/` (gitignored by default).

## Build from source

```sh
make tidy
make build
make run
```

Requires Go 1.22+.

## Roadmap

See [ROADMAP.md](ROADMAP.md). Yubikey / WebAuthn support is the next major item after v1.

## License

TBD.
