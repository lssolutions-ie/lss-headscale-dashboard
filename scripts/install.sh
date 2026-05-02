#!/usr/bin/env sh
# LSS Headscale Dashboard one-stop installer.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lssolutions-ie/lss-headscale-dashboard/main/scripts/install.sh | sudo sh
#
# After this script finishes, the dashboard is reachable at http://<server-ip>/setup.
# It installs and configures everything on this host: binary, systemd unit,
# nginx reverse proxy, optional fail2ban filter, and opens UFW port 80 if active.
#
# Environment overrides:
#   LSS_VERSION     release tag to install   (default: latest)
#   LSS_PREFIX      binary install prefix    (default: /usr/local/bin)
#   LSS_USER        service user             (default: lss-dashboard)
#   LSS_NO_NGINX=1  skip nginx install (you'll need your own reverse proxy)

set -eu

REPO="lssolutions-ie/lss-headscale-dashboard"
VERSION="${LSS_VERSION:-latest}"
PREFIX="${LSS_PREFIX:-/usr/local/bin}"
SVC_USER="${LSS_USER:-lss-dashboard}"
CONF_DIR="/etc/lss-headscale-dashboard"
DATA_DIR="/var/lib/lss-headscale-dashboard"
UNIT="/etc/systemd/system/lss-headscale-dashboard.service"
NGINX_SITE="/etc/nginx/sites-available/lss-headscale-dashboard"

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
    if [ ! -f "$CONF_DIR/config.yaml" ] && [ -f "$TMP/config.example.yaml" ]; then
        install -m 0640 "$TMP/config.example.yaml" "$CONF_DIR/config.yaml"
    fi
    chown -R "$SVC_USER":"$SVC_USER" "$DATA_DIR" "$CONF_DIR"
}

install_systemd() {
    # Only set SupplementaryGroups=headscale when the headscale group exists,
    # otherwise systemd refuses to start the unit (status=216/GROUP).
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
    systemctl enable --now lss-headscale-dashboard.service
}

install_nginx() {
    if [ "${LSS_NO_NGINX:-}" = "1" ]; then
        echo "  · LSS_NO_NGINX=1, skipping nginx setup"
        return
    fi

    if ! command -v nginx >/dev/null 2>&1; then
        echo "  · installing nginx"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq nginx >/dev/null
    fi

    cat >"$NGINX_SITE" <<EOF
# Managed by lss-headscale-dashboard installer. Edits will be overwritten on re-install.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    location /static/ {
        alias $DATA_DIR/static/;
        access_log off;
        expires 7d;
    }

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$http_x_forwarded_proto;
        proxy_read_timeout 60s;
    }
}
EOF
    ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/lss-headscale-dashboard

    # Drop Ubuntu's stock default site if present so our default_server captures :80.
    if [ -L /etc/nginx/sites-enabled/default ]; then
        rm /etc/nginx/sites-enabled/default
    fi

    if ! nginx -t 2>&1 | tail -2 | grep -q 'successful'; then
        echo "error: nginx config test failed" >&2
        nginx -t >&2 || true
        exit 1
    fi
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl reload nginx 2>/dev/null || systemctl restart nginx
}

open_firewall() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -q "Status: active"; then
        echo "  · ufw is active, allowing 80/tcp"
        ufw allow 80/tcp >/dev/null
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

# Detect the IP a remote client on the LAN would use to reach this host.
detect_lan_ip() {
    LAN_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") print $(i+1); exit}')"
    if [ -z "$LAN_IP" ]; then
        LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    fi
    [ -z "$LAN_IP" ] && LAN_IP="<server-ip>"
    echo "$LAN_IP"
}

# Poll http://127.0.0.1/setup (through nginx) until the wizard responds.
# If anything along the chain is broken, dump logs and exit non-zero.
health_check() {
    URL="http://127.0.0.1/setup"
    if [ "${LSS_NO_NGINX:-}" = "1" ]; then
        URL="http://127.0.0.1:9000/setup"
    fi
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
    if command -v nginx >/dev/null 2>&1; then
        echo "--- nginx -t ---" >&2
        nginx -t 2>&1 | head -5 >&2 || true
    fi
    exit 1
}

require_root
resolve_version
echo "Installing LSS Headscale Dashboard $VERSION"
ensure_user
install_binary
install_systemd
install_nginx
open_firewall
install_fail2ban
health_check

LAN_IP="$(detect_lan_ip)"
cat <<EOF

LSS Headscale Dashboard $VERSION is up.

  Open: http://$LAN_IP/setup

  Service:  systemctl status lss-headscale-dashboard
  Logs:     journalctl -u lss-headscale-dashboard -f
  Config:   $CONF_DIR/config.yaml
  Data:     $DATA_DIR

EOF
