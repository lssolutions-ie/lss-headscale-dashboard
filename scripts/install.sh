#!/usr/bin/env sh
# LSS Headscale Dashboard one-line installer.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lssolutions-ie/lss-headscale-dashboard/main/scripts/install.sh | sudo sh
#
# Environment overrides:
#   LSS_VERSION   release tag to install (default: latest)
#   LSS_PREFIX    binary install prefix (default: /usr/local/bin)
#   LSS_USER      service user (default: lss-dashboard)

set -eu

REPO="lssolutions-ie/lss-headscale-dashboard"
VERSION="${LSS_VERSION:-latest}"
PREFIX="${LSS_PREFIX:-/usr/local/bin}"
SVC_USER="${LSS_USER:-lss-dashboard}"
CONF_DIR="/etc/lss-headscale-dashboard"
DATA_DIR="/var/lib/lss-headscale-dashboard"
UNIT="/etc/systemd/system/lss-headscale-dashboard.service"

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "error: install.sh must run as root (try: sudo sh)" >&2
        exit 1
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
        *) echo "error: unsupported arch $(uname -m)" >&2; exit 1 ;;
    esac
}

detect_os() {
    case "$(uname -s)" in
        Linux) echo linux ;;
        *) echo "error: unsupported OS $(uname -s) (linux only for now)" >&2; exit 1 ;;
    esac
}

resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
        if [ -z "$VERSION" ]; then
            echo "error: could not resolve latest version" >&2
            exit 1
        fi
    fi
}

ensure_user() {
    if ! id "$SVC_USER" >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
    fi
    # Allow reading Headscale's unix socket if local.
    if getent group headscale >/dev/null 2>&1; then
        usermod -a -G headscale "$SVC_USER" || true
    fi
}

install_binary() {
    OS="$(detect_os)"
    ARCH="$(detect_arch)"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/lss-headscale-dashboard_${OS}_${ARCH}.tar.gz"
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    echo "downloading $URL"
    curl -fsSL "$URL" -o "$TMP/release.tar.gz"
    tar -xzf "$TMP/release.tar.gz" -C "$TMP"
    install -m 0755 "$TMP/lss-headscale-dashboard" "$PREFIX/lss-headscale-dashboard"
    mkdir -p "$CONF_DIR" "$DATA_DIR"
    if [ ! -f "$CONF_DIR/config.yaml" ] && [ -f "$TMP/config.example.yaml" ]; then
        install -m 0640 "$TMP/config.example.yaml" "$CONF_DIR/config.yaml"
    fi
    chown -R "$SVC_USER":"$SVC_USER" "$DATA_DIR" "$CONF_DIR"
}

install_systemd() {
    cat >"$UNIT" <<'EOF'
[Unit]
Description=LSS Headscale Dashboard
After=network.target headscale.service
Wants=network.target

[Service]
Type=simple
User=__SVC_USER__
Group=__SVC_USER__
ExecStart=__PREFIX__/lss-headscale-dashboard --config /etc/lss-headscale-dashboard/config.yaml
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/lss-headscale-dashboard
SupplementaryGroups=headscale

[Install]
WantedBy=multi-user.target
EOF
    sed -i "s#__SVC_USER__#$SVC_USER#g; s#__PREFIX__#$PREFIX#g" "$UNIT"
    systemctl daemon-reload
    systemctl enable --now lss-headscale-dashboard.service
}

install_fail2ban() {
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        echo "fail2ban not detected — skipping (filter is shipped at /usr/share/lss-headscale-dashboard/)"
        return
    fi
    TMP_F2B="$(mktemp -d)"
    trap 'rm -rf "$TMP_F2B"' EXIT
    URL_BASE="https://raw.githubusercontent.com/${REPO}/${VERSION}/deploy/fail2ban"
    curl -fsSL "$URL_BASE/filter.d/lss-headscale-dashboard.conf" \
        -o /etc/fail2ban/filter.d/lss-headscale-dashboard.conf
    if [ ! -f /etc/fail2ban/jail.d/lss-headscale-dashboard.conf ]; then
        curl -fsSL "$URL_BASE/jail.d/lss-headscale-dashboard.conf" \
            -o /etc/fail2ban/jail.d/lss-headscale-dashboard.conf
    fi
    systemctl reload fail2ban || true
}

require_root
resolve_version
ensure_user
install_binary
install_systemd
install_fail2ban

cat <<EOF

LSS Headscale Dashboard ${VERSION} installed.

Next: complete the first-run wizard.

  Local:  open http://127.0.0.1:9000/setup
  Remote: ssh -L 9000:127.0.0.1:9000 user@$(hostname)
          then open http://127.0.0.1:9000/setup on your laptop

Service:  systemctl status lss-headscale-dashboard
Logs:     journalctl -u lss-headscale-dashboard -f
Config:   ${CONF_DIR}/config.yaml

EOF
