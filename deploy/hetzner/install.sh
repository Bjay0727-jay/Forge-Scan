#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# ForgeScan External Scanner — Hetzner CX22 Install Script
#
# Installs the ForgeScan scanner as a Docker container with
# host networking for raw socket access (SYN scanning).
#
# Prerequisites:
#   - Fresh Ubuntu 22.04/24.04 or Debian 12 Hetzner VPS
#   - Root or sudo access
#   - Scanner registered in ForgeScan dashboard (get API key + ID)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Bjay0727-jay/Forge-Scan/main/deploy/hetzner/install.sh | \
#     sudo bash -s -- \
#       --api-key <SCANNER_API_KEY> \
#       --scanner-id <SCANNER_ID> \
#       --platform https://forgescan-api.stanley-riley.workers.dev
# ──────────────────────────────────────────────────────────────

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────
FORGESCAN_IMAGE="ghcr.io/bjay0727-jay/forgescan-scanner:latest"
FORGESCAN_PLATFORM="https://forgescan-api.stanley-riley.workers.dev"
FORGESCAN_API_KEY=""
FORGESCAN_SCANNER_ID=""
INSTALL_DIR="/etc/forgescan"
DATA_DIR="/var/lib/forgescan"
USE_SEALEDTUNNEL=false
STLINK_CONFIG=""

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[ForgeScan]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
banner() {
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════════════════╗"
    echo "  ║  ForgeScan 360 — External Scanner Installer       ║"
    echo "  ║  Hetzner Cloud Edition                            ║"
    echo "  ╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Parse arguments ───────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --api-key)            FORGESCAN_API_KEY="$2"; shift 2 ;;
        --scanner-id)         FORGESCAN_SCANNER_ID="$2"; shift 2 ;;
        --platform)           FORGESCAN_PLATFORM="$2"; shift 2 ;;
        --image)              FORGESCAN_IMAGE="$2"; shift 2 ;;
        --use-sealedtunnel)   USE_SEALEDTUNNEL=true; shift ;;
        --stlink-config)      STLINK_CONFIG="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 --api-key <KEY> --scanner-id <ID> [--platform <URL>] [--image <IMG>]"
            echo "       [--use-sealedtunnel --stlink-config <PATH>]"
            exit 0
            ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

banner

# ── Validate required inputs ─────────────────────────────────
if [[ -z "$FORGESCAN_API_KEY" ]]; then
    err "Missing --api-key. Register scanner in ForgeScan dashboard first."
    exit 1
fi
if [[ -z "$FORGESCAN_SCANNER_ID" ]]; then
    err "Missing --scanner-id. Register scanner in ForgeScan dashboard first."
    exit 1
fi

# ── SealedTunnel mode: override platform URL ──────────────────
if [[ "$USE_SEALEDTUNNEL" == "true" ]]; then
    FORGESCAN_PLATFORM="http://127.0.0.5:443"
    log "SealedTunnel mode ENABLED — platform URL overridden to loopback"
fi

log "Platform:   $FORGESCAN_PLATFORM"
log "Scanner ID: $FORGESCAN_SCANNER_ID"
log "Image:      $FORGESCAN_IMAGE"
if [[ "$USE_SEALEDTUNNEL" == "true" ]]; then
    log "Tunnel:     Xiid SealedTunnel via STLink (127.0.0.5:443)"
fi

# ── Check root ────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (or with sudo)"
    exit 1
fi

# ── Install Docker if not present ─────────────────────────────
if ! command -v docker &>/dev/null; then
    log "Installing Docker..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg

    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    log "Docker installed successfully"
else
    log "Docker already installed: $(docker --version)"
fi

# ── Create config directory ───────────────────────────────────
mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR"

# ── Write environment file (restricted permissions) ───────────
cat > "${INSTALL_DIR}/scanner.env" <<EOF
FORGESCAN_SCANNER_API_KEY=${FORGESCAN_API_KEY}
FORGESCAN_SCANNER_ID=${FORGESCAN_SCANNER_ID}
FORGESCAN_PLATFORM_URL=${FORGESCAN_PLATFORM}
FORGESCAN_DATA_DIR=/var/lib/forgescan
FORGESCAN_LOG_LEVEL=info
EOF
chmod 600 "${INSTALL_DIR}/scanner.env"
log "Config written to ${INSTALL_DIR}/scanner.env (mode 600)"

# ── Install STLink if SealedTunnel mode ───────────────────────
if [[ "$USE_SEALEDTUNNEL" == "true" ]]; then
    log "Setting up Xiid SealedTunnel STLink client..."
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    STLINK_SCRIPT="${SCRIPT_DIR}/../xiid/install-stlink-scanner.sh"

    if [[ -f "$STLINK_SCRIPT" ]]; then
        bash "$STLINK_SCRIPT" \
            --stlink-config "${STLINK_CONFIG}" \
            --loopback-ip 127.0.0.5 \
            --loopback-port 443
    else
        warn "STLink install script not found at $STLINK_SCRIPT"
        warn "Install STLink manually — see deploy/xiid/README.md"
    fi
fi

# ── Pull scanner image ────────────────────────────────────────
log "Pulling scanner image..."
docker pull "$FORGESCAN_IMAGE"

# ── Create systemd service ────────────────────────────────────
cat > /etc/systemd/system/forgescan-scanner.service <<EOF
[Unit]
Description=ForgeScan External Scanner
Documentation=https://github.com/Bjay0727-jay/Forge-Scan
After=network-online.target docker.service$(if [[ "$USE_SEALEDTUNNEL" == "true" ]]; then echo " stlink.service"; fi)
Wants=network-online.target
Requires=docker.service$(if [[ "$USE_SEALEDTUNNEL" == "true" ]]; then echo "\nRequires=stlink.service"; fi)

[Service]
Type=simple
TimeoutStartSec=300
Restart=always
RestartSec=10

# Stop any existing container on (re)start
ExecStartPre=-/usr/bin/docker stop forgescan-scanner
ExecStartPre=-/usr/bin/docker rm forgescan-scanner

ExecStart=/usr/bin/docker run \
    --name forgescan-scanner \
    --network host \
    --cap-add NET_RAW \
    --cap-add NET_ADMIN \
    --env-file ${INSTALL_DIR}/scanner.env \
    --volume forgescan-nvd:/var/lib/forgescan \
    --restart unless-stopped \
    ${FORGESCAN_IMAGE} \
    --platform ${FORGESCAN_PLATFORM} \
    --log-level info

ExecStop=/usr/bin/docker stop forgescan-scanner

[Install]
WantedBy=multi-user.target
EOF

# ── Enable and start ──────────────────────────────────────────
systemctl daemon-reload
systemctl enable forgescan-scanner.service
systemctl start forgescan-scanner.service

log "Scanner service started!"
echo ""
log "Check status:  systemctl status forgescan-scanner"
log "View logs:     journalctl -u forgescan-scanner -f"
log "Update image:  docker pull ${FORGESCAN_IMAGE} && systemctl restart forgescan-scanner"
echo ""
echo -e "${GREEN}  Scanner should appear in the ForgeScan dashboard within 30 seconds.${NC}"
