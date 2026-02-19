#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# ForgeScan Infra VM — Xiid Commander + STLink Exitpoint + Caddy
#
# Installs the full SealedTunnel infrastructure on forgescan-infra:
#   1. Xiid Commander (management plane, binds to private IP)
#   2. STLink (exitpoint mode, receives tunnel traffic)
#   3. Caddy (reverse proxy: STLink loopback → Cloudflare Workers API)
#
# Prerequisites:
#   - Fresh Ubuntu 22.04/24.04 Hetzner CX22 VM
#   - Root access
#   - Xiid Commander activation code
#   - VM attached to Hetzner Cloud Network (10.0.1.0/24)
#
# Usage:
#   ./install-infra.sh \
#     --commander-activation <XIID_ACTIVATION_CODE> \
#     --connector-fleet-url <XIID_CONNECTOR_URL> \
#     --private-ip 10.0.1.20 \
#     --platform-api https://forgescan-api.stanley-riley.workers.dev
# ──────────────────────────────────────────────────────────────

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────
COMMANDER_ACTIVATION=""
CONNECTOR_FLEET_URL=""
PRIVATE_IP="10.0.1.20"
PLATFORM_API="https://forgescan-api.stanley-riley.workers.dev"
STLINK_EXITPOINT_PORT_EXT="8443"
STLINK_EXITPOINT_PORT_ONPREM="8444"
INSTALL_DIR="/opt/xiid"
CONFIG_DIR="/etc/xiid"

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[ForgeScan/Xiid]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
banner() {
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════════════════╗"
    echo "  ║  ForgeScan 360 — Xiid SealedTunnel Infra Setup   ║"
    echo "  ║  Commander + STLink Exitpoint + Caddy             ║"
    echo "  ╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Parse arguments ───────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --commander-activation) COMMANDER_ACTIVATION="$2"; shift 2 ;;
        --connector-fleet-url)  CONNECTOR_FLEET_URL="$2"; shift 2 ;;
        --private-ip)           PRIVATE_IP="$2"; shift 2 ;;
        --platform-api)         PLATFORM_API="$2"; shift 2 ;;
        --ext-port)             STLINK_EXITPOINT_PORT_EXT="$2"; shift 2 ;;
        --onprem-port)          STLINK_EXITPOINT_PORT_ONPREM="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 --commander-activation <CODE> --connector-fleet-url <URL> [--private-ip <IP>]"
            exit 0
            ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

banner

# ── Validate ──────────────────────────────────────────────────
if [[ -z "$COMMANDER_ACTIVATION" ]]; then
    err "Missing --commander-activation. Get this from Xiid."
    exit 1
fi
if [[ -z "$CONNECTOR_FLEET_URL" ]]; then
    err "Missing --connector-fleet-url. Get this from Xiid."
    exit 1
fi
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (or with sudo)"
    exit 1
fi

log "Private IP:        $PRIVATE_IP"
log "Platform API:      $PLATFORM_API"
log "Ext exitpoint:     127.0.0.1:$STLINK_EXITPOINT_PORT_EXT"
log "On-prem exitpoint: 127.0.0.1:$STLINK_EXITPOINT_PORT_ONPREM"

# ── Install system dependencies ───────────────────────────────
log "Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg debian-keyring debian-archive-keyring apt-transport-https

# ── Create directories ────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"

# ══════════════════════════════════════════════════════════════
# STEP 1: Install Caddy (reverse proxy)
# ══════════════════════════════════════════════════════════════
log "Installing Caddy..."
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update -qq
apt-get install -y -qq caddy

# Write Caddyfile for reverse proxy
cat > /etc/caddy/Caddyfile <<EOF
# ForgeScan SealedTunnel Exitpoint — Caddy Reverse Proxy
#
# Receives decrypted tunnel traffic on loopback and proxies to Cloudflare Workers API.
# STLink provides encryption for the tunnel; Caddy re-encrypts to Cloudflare with TLS.

# External scanner tunnel exitpoint
http://127.0.0.1:${STLINK_EXITPOINT_PORT_EXT} {
    reverse_proxy ${PLATFORM_API} {
        header_up Host {upstream_hostport}
        transport http {
            tls
            tls_server_name $(echo "$PLATFORM_API" | sed 's|https://||' | sed 's|/.*||')
        }
    }
    log {
        output file /var/log/caddy/forgescan-ext.log
        level WARN
    }
}

# On-prem scanner tunnel exitpoint
http://127.0.0.1:${STLINK_EXITPOINT_PORT_ONPREM} {
    reverse_proxy ${PLATFORM_API} {
        header_up Host {upstream_hostport}
        transport http {
            tls
            tls_server_name $(echo "$PLATFORM_API" | sed 's|https://||' | sed 's|/.*||')
        }
    }
    log {
        output file /var/log/caddy/forgescan-onprem.log
        level WARN
    }
}
EOF

mkdir -p /var/log/caddy
log "Caddy configured with reverse proxy to $PLATFORM_API"

# ══════════════════════════════════════════════════════════════
# STEP 2: Xiid Commander placeholder
# ══════════════════════════════════════════════════════════════
log ""
log "═══════════════════════════════════════════════════════"
log "  XIID COMMANDER INSTALLATION"
log "═══════════════════════════════════════════════════════"
log ""
log "Xiid Commander must be installed manually using the"
log "Xiid-provided installer. Follow these steps:"
log ""
log "  1. Upload the Commander installer to this VM"
log "  2. Run the installer with activation code:"
log "     ./xiid-commander-install --activation $COMMANDER_ACTIVATION"
log "  3. Bind Commander to private IP only:"
log "     Configure listening address: $PRIVATE_IP"
log "  4. Set Connector Fleet URL:"
log "     $CONNECTOR_FLEET_URL"
log ""
log "Commander activation code: $COMMANDER_ACTIVATION"
log ""

# Save activation code for reference
cat > "${CONFIG_DIR}/commander.env" <<EOF
XIID_COMMANDER_ACTIVATION=${COMMANDER_ACTIVATION}
XIID_CONNECTOR_FLEET_URL=${CONNECTOR_FLEET_URL}
XIID_COMMANDER_BIND_IP=${PRIVATE_IP}
EOF
chmod 600 "${CONFIG_DIR}/commander.env"

# ══════════════════════════════════════════════════════════════
# STEP 3: STLink exitpoint placeholder
# ══════════════════════════════════════════════════════════════
log ""
log "═══════════════════════════════════════════════════════"
log "  XIID STLINK EXITPOINT INSTALLATION"
log "═══════════════════════════════════════════════════════"
log ""
log "STLink must be installed manually using the"
log "Xiid-provided installer. Follow these steps:"
log ""
log "  1. Upload the STLink installer to this VM"
log "  2. Run the installer with activation code from Commander"
log "  3. Configure exitpoint tunnel mappings:"
log "     - External scanner:  bind 127.0.0.1:${STLINK_EXITPOINT_PORT_EXT}"
log "     - On-prem scanner:   bind 127.0.0.1:${STLINK_EXITPOINT_PORT_ONPREM}"
log ""

# ══════════════════════════════════════════════════════════════
# STEP 4: Start Caddy
# ══════════════════════════════════════════════════════════════
systemctl enable caddy
systemctl restart caddy
log "Caddy started and enabled"

# ══════════════════════════════════════════════════════════════
# STEP 5: Firewall recommendations
# ══════════════════════════════════════════════════════════════
log ""
log "═══════════════════════════════════════════════════════"
log "  HETZNER FIREWALL SETUP"
log "═══════════════════════════════════════════════════════"
log ""
log "Run these commands from your local machine:"
log ""
log "  # Create firewall"
log "  hcloud firewall create --name forgescan-infra-fw"
log ""
log "  # Allow SSH from admin IP only"
log "  hcloud firewall add-rule forgescan-infra-fw \\"
log "    --direction in --protocol tcp --port 22 \\"
log "    --source-ips <YOUR_ADMIN_IP>/32 --description 'SSH admin'"
log ""
log "  # Apply to infra VM"
log "  hcloud firewall apply-to-resource forgescan-infra-fw \\"
log "    --type server --server forgescan-infra"
log ""
log "  No inbound ports needed for the tunnel — STLink and Caddy"
log "  only make outbound connections."
log ""

log "Infrastructure setup complete!"
log ""
log "Next steps:"
log "  1. Install Xiid Commander (see instructions above)"
log "  2. Install STLink exitpoint (see instructions above)"
log "  3. Create tunnel mappings in Commander portal"
log "  4. Install STLink on scanner VMs"
