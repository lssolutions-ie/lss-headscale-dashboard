#!/usr/bin/env sh
# LSS Headscale Dashboard one-stop installer.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lssolutions-ie/lss-headscale-dashboard/main/scripts/install.sh | sudo sh
#
# After this script finishes, the dashboard is reachable at http://<server-ip>:9000/setup.
# The Go app binds directly to 0.0.0.0:9000. If you put HAProxy/nginx in front,
# change `listen` in /etc/lss-headscale-dashboard/config.yaml to 127.0.0.1:9000.
#
# Environment overrides:
#   LSS_VERSION  release tag to install (default: latest)
#   LSS_PREFIX   binary install prefix  (default: /usr/local/bin)
#   LSS_USER     service user           (default: lss-dashboard)
#   LSS_PORT     port to bind on        (default: 9000)

set -eu

REPO="lssolutions-ie/lss-headscale-dashboard"
VERSION="${LSS_VERSION:-latest}"
PREFIX="${LSS_PREFIX:-/usr/local/bin}"
SVC_USER="${LSS_USER:-lss-dashboard}"
PORT="${LSS_PORT:-9000}"
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
        *) echo "error: unsupported OS $(uname -s) (linux only)" >&2; exit 1 ;;
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
    if getent group headscale >/dev/null 2>&1; then
        usermod -a -G headscale "$SVC_USER" 2>/dev/null || true
    fi
}

install_binary() {
    OS="$(detect_os)"
    ARCH="$(detect_arch)"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/lss-headscale-dashboard_${OS}_${ARCH}.tar.gz"
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    echo "  · downloading $URL"
    curl -fsSL "$URL" -o "$TMP/release.tar.gz"
    tar -xzf "$TMP/release.tar.gz" -C "$TMP"
    install -m 0755 "$TMP/lss-headscale-dashboard" "$PREFIX/lss-headscale-dashboard"
    mkdir -p "$CONF_DIR" "$DATA_DIR"
    write_config
    chown -R "$SVC_USER":"$SVC_USER" "$DATA_DIR" "$CONF_DIR"
}

# Install-script-owned config.yaml. Schema is documented in config.example.yaml.
# Existing config is preserved (idempotent).
write_config() {
    if [ -f "$CONF_DIR/config.yaml" ]; then
        return
    fi
    cat >"$CONF_DIR/config.yaml" <<EOF
listen: 0.0.0.0:$PORT
data_dir: $DATA_DIR
log_level: info
EOF
    chmod 0640 "$CONF_DIR/config.yaml"
}

install_systemd() {
    SUPP_GROUPS_LINE=""
    if getent group headscale >/dev/null 2>&1; then
        SUPP_GROUPS_LINE="SupplementaryGroups=headscale"
    fi

    cat >"$UNIT" <<EOF
[Unit]
Description=LSS Headscale Dashboard
After=network.target headscale.service
Wants=network.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
ExecStart=$PREFIX/lss-headscale-dashboard --config $CONF_DIR/config.yaml
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=$DATA_DIR
$SUPP_GROUPS_LINE

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable lss-headscale-dashboard.service
    # Use restart (not start) so re-runs reload the new binary on upgrade.
    systemctl restart lss-headscale-dashboard.service
}

# Remove an nginx site that previous installers (v0.1.2) wrote.
# We do not uninstall nginx itself — leaving it installed is harmless.
cleanup_old_nginx_site() {
    SITE_AVAIL=/etc/nginx/sites-available/lss-headscale-dashboard
    SITE_ENABLED=/etc/nginx/sites-enabled/lss-headscale-dashboard
    if [ -e "$SITE_AVAIL" ] || [ -L "$SITE_ENABLED" ]; then
        echo "  · removing old nginx site (dashboard now binds :$PORT directly)"
        rm -f "$SITE_AVAIL" "$SITE_ENABLED"
        # Restore Ubuntu's default site if it was disabled by the old installer.
        if [ -f /etc/nginx/sites-available/default ] && [ ! -L /etc/nginx/sites-enabled/default ]; then
            ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
        fi
        if command -v nginx >/dev/null 2>&1; then
            nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true
        fi
    fi
}

open_firewall() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -q "Status: active"; then
        echo "  · ufw is active, allowing $PORT/tcp"
        ufw allow "$PORT/tcp" >/dev/null
    fi
}

install_fail2ban() {
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        return
    fi
    URL_BASE="https://raw.githubusercontent.com/${REPO}/${VERSION}/deploy/fail2ban"
    curl -fsSL "$URL_BASE/filter.d/lss-headscale-dashboard.conf" \
        -o /etc/fail2ban/filter.d/lss-headscale-dashboard.conf
    if [ ! -f /etc/fail2ban/jail.d/lss-headscale-dashboard.conf ]; then
        curl -fsSL "$URL_BASE/jail.d/lss-headscale-dashboard.conf" \
            -o /etc/fail2ban/jail.d/lss-headscale-dashboard.conf
    fi
    systemctl reload fail2ban 2>/dev/null || true
    echo "  · fail2ban filter installed"
}

detect_lan_ip() {
    LAN_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") print $(i+1); exit}')"
    if [ -z "$LAN_IP" ]; then
        LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    fi
    [ -z "$LAN_IP" ] && LAN_IP="<server-ip>"
    echo "$LAN_IP"
}

health_check() {
    URL="http://127.0.0.1:$PORT/setup"
    echo "  · waiting for dashboard at $URL"
    i=0
    while [ $i -lt 15 ]; do
        code="$(curl -s -o /dev/null -w '%{http_code}' -m 2 "$URL" 2>/dev/null || echo 000)"
        if [ "$code" = "200" ]; then
            echo "  ✓ dashboard reachable"
            return 0
        fi
        sleep 1
        i=$((i+1))
    done
    echo >&2
    echo "ERROR: dashboard did not respond at $URL within 15s." >&2
    echo "--- systemctl status lss-headscale-dashboard ---" >&2
    systemctl status lss-headscale-dashboard --no-pager -l 2>&1 | head -15 >&2 || true
    echo "--- recent logs ---" >&2
    journalctl -u lss-headscale-dashboard --no-pager -n 20 2>&1 >&2 || true
    exit 1
}

require_root
resolve_version
echo "Installing LSS Headscale Dashboard $VERSION"
ensure_user
install_binary
install_systemd
cleanup_old_nginx_site
open_firewall
install_fail2ban
health_check

LAN_IP="$(detect_lan_ip)"
cat <<EOF

LSS Headscale Dashboard $VERSION is up.

  Open: http://$LAN_IP:$PORT/setup

  Service:  systemctl status lss-headscale-dashboard
  Logs:     journalctl -u lss-headscale-dashboard -f
  Config:   $CONF_DIR/config.yaml
  Data:     $DATA_DIR

EOF
