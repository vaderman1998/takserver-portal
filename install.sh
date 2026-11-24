#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────
#  TAK Server Portal — Installer
#  Upgrade + certificate management for a native TAK Server.
#  Installs dependencies, configures systemd, and starts the
#  portal. Supports Debian/Ubuntu and RHEL/Rocky/Alma.
# ─────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Pre-flight checks ────────────────────────────────────────
[[ $EUID -eq 0 ]] || error "This script must be run as root."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_PY="$SCRIPT_DIR/app.py"
[[ -f "$APP_PY" ]] || error "app.py not found in $SCRIPT_DIR. Run this script from inside the portal folder."
[[ -f "$SCRIPT_DIR/takcerts.py" ]] || error "takcerts.py not found next to app.py."

INSTALL_DIR="$SCRIPT_DIR"
SERVICE_NAME="tak-portal"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# ── Detect OS family ─────────────────────────────────────────
OS_FAMILY="unknown"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}${ID_LIKE:-}" in
        *debian*|*ubuntu*) OS_FAMILY="debian" ;;
        *rhel*|*fedora*|*centos*) OS_FAMILY="rhel" ;;
    esac
fi

if [[ "$OS_FAMILY" == "unknown" ]]; then
    if command -v apt-get &>/dev/null; then
        OS_FAMILY="debian"
    elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then
        OS_FAMILY="rhel"
    else
        error "Unsupported OS. This installer requires a Debian/Ubuntu or RHEL/Rocky/Alma system."
    fi
fi

info "Detected OS family: $OS_FAMILY (${PRETTY_NAME:-$ID})"
info "Installing TAK Server Portal from: $INSTALL_DIR"

# ── Python: the newest 3.x on the box (3.6 works; 3.9+ is better) ──
if ! command -v python3 &>/dev/null; then
    info "Python 3 not found, installing..."
    if [[ "$OS_FAMILY" == "debian" ]]; then
        apt-get update -qq
        apt-get install -y -qq python3
    else
        dnf install -y -q python3
    fi
fi
PYTHON=""
for cand in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$cand" &>/dev/null; then PYTHON="$(command -v "$cand")"; break; fi
done
[[ -n "$PYTHON" ]] || error "No python3 interpreter found."
PYVER="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
info "Using $PYTHON (Python $PYVER)"
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' \
    || error "Python $PYVER is too old; the portal needs 3.6 or newer."
if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
    warn "Python $PYVER is end-of-life. The portal runs on it, but a newer one is one package away:"
    if [[ "$OS_FAMILY" == "rhel" ]]; then
        warn "  dnf install -y python3.11   (then run this installer again; it picks the newest python3.x)"
    else
        warn "  apt-get install -y python3"
    fi
fi

# ── Verify Python has ssl support ─────────────────────────────
"$PYTHON" -c "import ssl" 2>/dev/null || {
    warn "Python ssl module not available, installing..."
    if [[ "$OS_FAMILY" == "debian" ]]; then
        apt-get update -qq
        apt-get install -y -qq python3-openssl libssl-dev
    else
        dnf install -y -q python3-pyOpenSSL openssl-devel
    fi
}

# ── Certificate tooling checks (TAK Server's own scripts need these) ──
if [[ -d /opt/tak/certs ]]; then
    info "TAK Server found at /opt/tak"
    id tak &>/dev/null || warn "No 'tak' user: certificate operations need a native TAK Server install."
    command -v openssl &>/dev/null || warn "openssl not found; certificate operations will refuse to run."
    command -v runuser &>/dev/null || warn "runuser not found (util-linux); certificate operations will refuse to run."
    if ! command -v keytool &>/dev/null && ! ls /usr/lib/jvm/*/bin/keytool &>/dev/null; then
        warn "keytool (Java) not found on PATH; TAK Server needs a JDK/JRE, so check /opt/tak/setenv.sh."
    fi
    command -v psql &>/dev/null || warn "psql not found; the 'Live certificates by CA' table will not load."
else
    warn "No /opt/tak/certs on this box: the portal will run, but certificate management stays disabled."
fi

# ── Create uploads directory and state file ───────────────────
mkdir -p "$INSTALL_DIR/uploads"
info "Uploads directory ready: $INSTALL_DIR/uploads"
touch "$INSTALL_DIR/portal-state.json"
chmod 600 "$INSTALL_DIR/portal-state.json"

# ── Detect Let's Encrypt certs ────────────────────────────────
CERT_DIR=""
if [[ -d /etc/letsencrypt/live ]]; then
    for d in /etc/letsencrypt/live/*/; do
        if [[ -f "${d}fullchain.pem" && -f "${d}privkey.pem" ]]; then
            CERT_DIR="$d"
            break
        fi
    done
fi

if [[ -n "$CERT_DIR" ]]; then
    info "Found Let's Encrypt certs: $CERT_DIR"
else
    warn "No Let's Encrypt certs found in /etc/letsencrypt/live/"
    warn "Portal will run in plain HTTP mode."
    warn "To add HTTPS later, install certbot and set TAK_PORTAL_CERT_DIR."
    CERT_DIR="/etc/letsencrypt/live/localhost"
fi

# ── Prompt for settings ───────────────────────────────────────
read -rp "Portal port [9090]: " INPUT_PORT
PORTAL_PORT="${INPUT_PORT:-9090}"

read -rp "Admin username [admin]: " INPUT_USER
PORTAL_USER="${INPUT_USER:-admin}"

read -rsp "Admin password [takadmin]: " INPUT_PASS
echo
PORTAL_PASS="${INPUT_PASS:-takadmin}"
[[ "$PORTAL_PASS" == "takadmin" ]] && warn "Using the default password. Change it: it also gates certificate rotation."

DEFAULT_FQDN="$(hostname -f 2>/dev/null || hostname)"
read -rp "TAK Server name for connection packages / certificate (FQDN) [$DEFAULT_FQDN]: " INPUT_FQDN
PORTAL_FQDN="${INPUT_FQDN:-$DEFAULT_FQDN}"
"$PYTHON" - "$INSTALL_DIR/portal-state.json" "$PORTAL_FQDN" <<'PY'
import json, sys
path, fqdn = sys.argv[1], sys.argv[2].strip().lower().rstrip('.')
try:
    st = json.load(open(path))
    if not isinstance(st, dict):
        st = {}
except Exception:
    st = {}
st['fqdn'] = fqdn
json.dump(st, open(path, 'w'), indent=2)
PY
chmod 600 "$INSTALL_DIR/portal-state.json"

# ── Create systemd unit ──────────────────────────────────────
info "Creating systemd service: $SERVICE_FILE"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=TAK Server Portal (upgrade + certificates)
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON -u ${INSTALL_DIR}/app.py
Restart=on-failure
RestartSec=5
UMask=0077
Environment=TAK_PORTAL_USER=$PORTAL_USER
Environment=TAK_PORTAL_PASS=$PORTAL_PASS
Environment=TAK_PORTAL_PORT=$PORTAL_PORT
Environment=TAK_PORTAL_CERT_DIR=$CERT_DIR
Environment=TAK_DIR=/opt/tak

[Install]
WantedBy=multi-user.target
EOF
chmod 600 "$SERVICE_FILE"

# ── Open firewall port ────────────────────────────────────────
if [[ "$OS_FAMILY" == "debian" ]]; then
    if command -v ufw &>/dev/null; then
        if ufw status | grep -q "Status: active"; then
            if ! ufw status | grep -q "$PORTAL_PORT/tcp"; then
                info "Opening port $PORTAL_PORT/tcp in UFW..."
                ufw allow "$PORTAL_PORT/tcp" comment "TAK Portal"
            else
                info "Port $PORTAL_PORT/tcp already open in UFW."
            fi
        fi
    fi
else
    if command -v firewall-cmd &>/dev/null; then
        if firewall-cmd --state &>/dev/null; then
            if ! firewall-cmd --query-port="$PORTAL_PORT/tcp" &>/dev/null; then
                info "Opening port $PORTAL_PORT/tcp in firewalld..."
                firewall-cmd --permanent --add-port="$PORTAL_PORT/tcp"
                firewall-cmd --reload
            else
                info "Port $PORTAL_PORT/tcp already open in firewalld."
            fi
        fi
    fi
fi

# ── Enable and start ─────────────────────────────────────────
info "Reloading systemd..."
systemctl daemon-reload

info "Enabling $SERVICE_NAME to start on boot..."
systemctl enable "$SERVICE_NAME"

systemctl stop "$SERVICE_NAME" 2>/dev/null || true

info "Starting $SERVICE_NAME..."
systemctl start "$SERVICE_NAME"
sleep 2

if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  TAK Server Portal installed successfully         ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo ""
    if [[ "$CERT_DIR" != "/etc/letsencrypt/live/localhost" ]]; then
        echo "  URL:      https://$(hostname -f):${PORTAL_PORT}"
    else
        echo "  URL:      http://$(hostname -f):${PORTAL_PORT}"
    fi
    echo "  User:     $PORTAL_USER"
    echo ""
    echo "  Manage with:"
    echo "    systemctl status  $SERVICE_NAME"
    echo "    systemctl restart $SERVICE_NAME"
    echo "    systemctl stop    $SERVICE_NAME"
    echo "    journalctl -u $SERVICE_NAME -f"
    echo ""
else
    error "Service failed to start. Check: journalctl -u $SERVICE_NAME -e"
fi
