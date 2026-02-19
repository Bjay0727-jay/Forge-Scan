#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# ForgeScan Internal Scanner — On-Premises Install Script
#
# Installs the ForgeScan scanner as a native Linux binary
# with systemd service for internal network scanning.
#
# Prerequisites:
#   - Ubuntu 22.04+, Debian 12+, RHEL 9+, or Rocky 9+
#   - Root or sudo access
#   - Outbound HTTPS access to forgescan-api.stanley-riley.workers.dev
#   - Scanner registered in ForgeScan dashboard (get API key + ID)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Bjay0727-jay/Forge-Scan/main/deploy/onprem/install.sh | \
#     sudo bash -s -- \
#       --api-key <SCANNER_API_KEY> \
#       --scanner-id <SCANNER_ID> \
#       --platform https://forgescan-api.stanley-riley.workers.dev
# ──────────────────────────────────────────────────────────────

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────
GITHUB_REPO="Bjay0727-jay/Forge-Scan"
FORGESCAN_PLATFORM="https://forgescan-api.stanley-riley.workers.dev"
FORGESCAN_API_KEY=""
FORGESCAN_SCANNER_ID=""
FORGESCAN_VERSION="latest"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/forgescan"
DATA_DIR="/var/lib/forgescan"
LOG_LEVEL="info"
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
    echo "  ║  ForgeScan 360 — Internal Scanner Installer       ║"
    echo "  ║  On-Premises Edition (Native Binary)              ║"
    echo "  ╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Parse arguments ───────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --api-key)            FORGESCAN_API_KEY="$2"; shift 2 ;;
        --scanner-id)         FORGESCAN_SCANNER_ID="$2"; shift 2 ;;
        --platform)           FORGESCAN_PLATFORM="$2"; shift 2 ;;
        --version)            FORGESCAN_VERSION="$2"; shift 2 ;;
        --log-level)          LOG_LEVEL="$2"; shift 2 ;;
        --use-sealedtunnel)   USE_SEALEDTUNNEL=true; shift ;;
        --stlink-config)      STLINK_CONFIG="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 --api-key <KEY> --scanner-id <ID> [--platform <URL>] [--version <TAG>]"
            echo "       [--use-sealedtunnel --stlink-config <PATH>]"
            exit 0
            ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

banner

# ── SealedTunnel mode: override platform URL ──────────────────
if [[ "$USE_SEALEDTUNNEL" == "true" ]]; then
    FORGESCAN_PLATFORM="http://127.0.0.5:443"
    log "SealedTunnel mode ENABLED — platform URL overridden to loopback"
fi

# ── Validate required inputs ─────────────────────────────────
if [[ -z "$FORGESCAN_API_KEY" ]]; then
    err "Missing --api-key. Register scanner in ForgeScan dashboard first."
    exit 1
fi
if [[ -z "$FORGESCAN_SCANNER_ID" ]]; then
    err "Missing --scanner-id. Register scanner in ForgeScan dashboard first."
    exit 1
fi

# ── Check root ────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (or with sudo)"
    exit 1
fi

# ── Detect architecture ───────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ASSET_NAME="forgescan-scanner-linux-amd64" ;;
    aarch64) ASSET_NAME="forgescan-scanner-linux-arm64" ;;
    *)       err "Unsupported architecture: $ARCH (need x86_64 or aarch64)"; exit 1 ;;
esac
log "Detected architecture: $ARCH → $ASSET_NAME"

# ── Install runtime dependencies ──────────────────────────────
log "Installing runtime dependencies..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq ca-certificates libpcap0.8 libssl3 curl jq
elif command -v dnf &>/dev/null; then
    dnf install -y -q ca-certificates libpcap openssl curl jq
elif command -v yum &>/dev/null; then
    yum install -y -q ca-certificates libpcap openssl curl jq
else
    warn "Unknown package manager. Ensure libpcap, openssl, curl, jq are installed."
fi

# ── Resolve version ───────────────────────────────────────────
if [[ "$FORGESCAN_VERSION" == "latest" ]]; then
    log "Fetching latest release version..."
    FORGESCAN_VERSION=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | jq -r '.tag_name')
    if [[ -z "$FORGESCAN_VERSION" || "$FORGESCAN_VERSION" == "null" ]]; then
        err "Could not determine latest version. Specify --version explicitly."
        exit 1
    fi
fi
log "Installing version: $FORGESCAN_VERSION"

# ── Download binary ───────────────────────────────────────────
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${FORGESCAN_VERSION}/${ASSET_NAME}.tar.gz"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

log "Downloading from: $DOWNLOAD_URL"
curl -fsSL "$DOWNLOAD_URL" -o "${TEMP_DIR}/${ASSET_NAME}.tar.gz"
tar xzf "${TEMP_DIR}/${ASSET_NAME}.tar.gz" -C "$TEMP_DIR"

# ── Install binary ────────────────────────────────────────────
install -m 0755 "${TEMP_DIR}/forgescan-scanner" "${INSTALL_DIR}/forgescan-scanner"
log "Binary installed to ${INSTALL_DIR}/forgescan-scanner"

# Verify
"${INSTALL_DIR}/forgescan-scanner" --version || warn "Binary may not be compatible with this system"

# ── Create system user ────────────────────────────────────────
if ! id -u forgescan &>/dev/null; then
    useradd -r -s /bin/false -d "$DATA_DIR" forgescan
    log "Created system user: forgescan"
fi

# ── Create directories ────────────────────────────────────────
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"
chown forgescan:forgescan "$DATA_DIR"

# ── Write config file ─────────────────────────────────────────
cat > "${CONFIG_DIR}/scanner.toml" <<EOF
# ForgeScan Scanner Configuration
# Generated by install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

[platform]
url = "${FORGESCAN_PLATFORM}"
scanner_id = "${FORGESCAN_SCANNER_ID}"
# API key is stored in scanner.env (not in this file)

[scanner]
log_level = "${LOG_LEVEL}"
data_dir = "${DATA_DIR}"
max_concurrent_tasks = 4
heartbeat_interval_secs = 30

[network]
scan_timeout_secs = 5
banner_grab = true
max_port_concurrency = 500
EOF
chmod 644 "${CONFIG_DIR}/scanner.toml"
log "Config written to ${CONFIG_DIR}/scanner.toml"

# ── Write environment file (secrets only) ─────────────────────
cat > "${CONFIG_DIR}/scanner.env" <<EOF
FORGESCAN_SCANNER_API_KEY=${FORGESCAN_API_KEY}
EOF
chmod 600 "${CONFIG_DIR}/scanner.env"
chown root:root "${CONFIG_DIR}/scanner.env"
log "API key stored in ${CONFIG_DIR}/scanner.env (mode 600)"

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

# ── Create systemd service ────────────────────────────────────
STLINK_UNIT_DEPS=""
if [[ "$USE_SEALEDTUNNEL" == "true" ]]; then
    STLINK_UNIT_DEPS="After=network-online.target stlink.service
Wants=network-online.target
Requires=stlink.service"
else
    STLINK_UNIT_DEPS="After=network-online.target
Wants=network-online.target"
fi

cat > /etc/systemd/system/forgescan-scanner.service <<EOF
[Unit]
Description=ForgeScan Internal Scanner
Documentation=https://github.com/Bjay0727-jay/Forge-Scan
${STLINK_UNIT_DEPS}

[Service]
Type=simple
User=forgescan
Group=forgescan
EnvironmentFile=${CONFIG_DIR}/scanner.env

# Raw socket capabilities (SYN scanning) without running as root
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

ExecStart=${INSTALL_DIR}/forgescan-scanner \
    --config ${CONFIG_DIR}/scanner.toml \
    --platform ${FORGESCAN_PLATFORM} \
    --log-level ${LOG_LEVEL}

Restart=always
RestartSec=10
TimeoutStopSec=30

# Security hardening
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
PrivateTmp=true
NoNewPrivileges=false
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

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
log "Config:        ${CONFIG_DIR}/scanner.toml"
log "NVD data:      ${DATA_DIR}/"
echo ""
log "Update scanner:"
log "  1. Download new binary from GitHub Releases"
log "  2. sudo install -m 0755 forgescan-scanner ${INSTALL_DIR}/forgescan-scanner"
log "  3. sudo systemctl restart forgescan-scanner"
echo ""
echo -e "${GREEN}  Scanner should appear in the ForgeScan dashboard within 30 seconds.${NC}"
