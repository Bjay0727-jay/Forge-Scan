#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# ForgeScan — Hetzner Cloud Infrastructure Provisioning
#
# Creates the Cloud Network, Infra VM, and Firewalls needed
# for the Xiid SealedTunnel deployment.
#
# Prerequisites:
#   - hcloud CLI installed and configured
#   - SSH key registered in Hetzner Cloud
#
# Usage:
#   ./hetzner-provision.sh --ssh-key my-key [--location fsn1]
# ──────────────────────────────────────────────────────────────

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────
SSH_KEY=""
LOCATION="fsn1"    # Falkenstein, Germany (cheapest)
SCANNER_VM="forgescan-scanner-ext"
INFRA_VM="forgescan-infra"
NETWORK_NAME="forgescan-internal"
SUBNET="10.0.1.0/24"
SCANNER_PRIVATE_IP="10.0.1.10"
INFRA_PRIVATE_IP="10.0.1.20"
SERVER_TYPE="cx22"

# ── Colors ────────────────────────────────────────────────────
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[Provision]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $*"; }

# ── Parse arguments ───────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --ssh-key)   SSH_KEY="$2"; shift 2 ;;
        --location)  LOCATION="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 --ssh-key <KEY_NAME> [--location <LOCATION>]"
            echo ""
            echo "Locations: fsn1 (Falkenstein), nbg1 (Nuremberg), hel1 (Helsinki), ash (Ashburn)"
            exit 0
            ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

if [[ -z "$SSH_KEY" ]]; then
    echo "Usage: $0 --ssh-key <KEY_NAME>"
    exit 1
fi

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════════════╗"
echo "  ║  ForgeScan — Hetzner Cloud Provisioning            ║"
echo "  ║  SealedTunnel Infrastructure                      ║"
echo "  ╚═══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ══════════════════════════════════════════════════════════════
# STEP 1: Create Cloud Network
# ══════════════════════════════════════════════════════════════
log "Creating Cloud Network: $NETWORK_NAME ($SUBNET)..."
if hcloud network describe "$NETWORK_NAME" &>/dev/null; then
    warn "Network $NETWORK_NAME already exists, skipping"
else
    hcloud network create --name "$NETWORK_NAME" --ip-range "10.0.0.0/16"
    hcloud network add-subnet "$NETWORK_NAME" --type cloud --network-zone eu-central --ip-range "$SUBNET"
    log "Network created"
fi

# ══════════════════════════════════════════════════════════════
# STEP 2: Create Infra VM (Commander + Exitpoint + Caddy)
# ══════════════════════════════════════════════════════════════
log "Creating Infra VM: $INFRA_VM ($SERVER_TYPE)..."
if hcloud server describe "$INFRA_VM" &>/dev/null; then
    warn "Server $INFRA_VM already exists, skipping"
else
    hcloud server create \
        --name "$INFRA_VM" \
        --type "$SERVER_TYPE" \
        --image ubuntu-22.04 \
        --location "$LOCATION" \
        --ssh-key "$SSH_KEY" \
        --network "$NETWORK_NAME"
    log "Infra VM created"

    # Assign specific private IP
    # Note: Hetzner auto-assigns from the subnet; to force a specific IP,
    # detach and re-attach with the desired IP
    log "Infra VM private IP will be auto-assigned from $SUBNET"
    log "To use $INFRA_PRIVATE_IP, configure it in the VM's network settings"
fi

# ══════════════════════════════════════════════════════════════
# STEP 3: Attach Scanner VM to Cloud Network (if not already)
# ══════════════════════════════════════════════════════════════
if hcloud server describe "$SCANNER_VM" &>/dev/null; then
    log "Attaching $SCANNER_VM to Cloud Network..."
    hcloud server attach-to-network "$SCANNER_VM" --network "$NETWORK_NAME" 2>/dev/null || \
        warn "$SCANNER_VM already attached to network"
else
    warn "Scanner VM $SCANNER_VM not found. Create it first or update the name."
fi

# ══════════════════════════════════════════════════════════════
# STEP 4: Create Firewalls
# ══════════════════════════════════════════════════════════════
log "Creating firewalls..."

# Scanner VM firewall
if ! hcloud firewall describe forgescan-scanner-fw &>/dev/null; then
    hcloud firewall create --name forgescan-scanner-fw
    hcloud firewall add-rule forgescan-scanner-fw \
        --direction in --protocol tcp --port 22 \
        --source-ips "0.0.0.0/0" --description "SSH (restrict to admin IP later)"
    log "Scanner firewall created (SSH open — restrict after setup)"

    if hcloud server describe "$SCANNER_VM" &>/dev/null; then
        hcloud firewall apply-to-resource forgescan-scanner-fw \
            --type server --server "$SCANNER_VM"
    fi
else
    warn "Scanner firewall already exists"
fi

# Infra VM firewall
if ! hcloud firewall describe forgescan-infra-fw &>/dev/null; then
    hcloud firewall create --name forgescan-infra-fw
    hcloud firewall add-rule forgescan-infra-fw \
        --direction in --protocol tcp --port 22 \
        --source-ips "0.0.0.0/0" --description "SSH (restrict to admin IP later)"
    log "Infra firewall created (SSH open — restrict after setup)"

    if hcloud server describe "$INFRA_VM" &>/dev/null; then
        hcloud firewall apply-to-resource forgescan-infra-fw \
            --type server --server "$INFRA_VM"
    fi
else
    warn "Infra firewall already exists"
fi

# ══════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════
echo ""
log "═══════════════════════════════════════════════════════"
log "  PROVISIONING COMPLETE"
log "═══════════════════════════════════════════════════════"
echo ""

INFRA_IP=$(hcloud server describe "$INFRA_VM" -o format='{{.PublicNet.IPv4.IP}}' 2>/dev/null || echo "<pending>")
SCANNER_IP=$(hcloud server describe "$SCANNER_VM" -o format='{{.PublicNet.IPv4.IP}}' 2>/dev/null || echo "<not found>")

log "Infrastructure:"
log "  Infra VM:    $INFRA_VM  →  $INFRA_IP"
log "  Scanner VM:  $SCANNER_VM  →  $SCANNER_IP"
log "  Network:     $NETWORK_NAME ($SUBNET)"
echo ""
log "Next steps:"
log "  1. SSH into infra VM:   ssh root@$INFRA_IP"
log "  2. Run install-infra.sh to install Commander + STLink + Caddy"
log "  3. Configure tunnels in Commander portal"
log "  4. Install STLink on scanner VM"
echo ""
log "Cost: ~\$4/mo for infra VM + ~\$4/mo for scanner VM = ~\$8/mo total"
