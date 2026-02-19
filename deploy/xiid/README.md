# ForgeScan 360 — Xiid SealedTunnel Deployment Guide

> Quantum-resistant, zero-inbound-port secure tunnel for all scanner-to-platform communication.

## Overview

Xiid SealedTunnel replaces direct HTTPS connections between ForgeScan scanners and the Cloudflare Workers API with a triple-encrypted, quantum-secure tunnel. Both sides establish **outbound-only** connections on port 443 — zero inbound ports required on any machine.

### Architecture

```
Scanner VM (Hetzner/On-Prem)          Xiid Connector Fleet (SaaS)        Infra VM (Hetzner)                Cloudflare
┌────────────────────────┐            ┌──────────────────┐               ┌─────────────────────────┐       ┌──────────┐
│ forgescan-scanner      │            │                  │               │ STLink exitpoint        │       │ Workers  │
│  → http://127.0.0.5:443│──outbound──│ Triple-encrypted │──outbound───>│  → 127.0.0.1:8443       │       │ API      │
│                        │   :443     │ Quantum-secure   │   :443       │                         │       │          │
│ STLink client          │            │ Auto-failover    │               │ Caddy reverse proxy     │──────>│          │
│  binds 127.0.0.5:443  │            │                  │               │  → Cloudflare Workers   │ :443  │          │
└────────────────────────┘            └──────────────────┘               ├─────────────────────────┤       └──────────┘
                                                                        │ Xiid Commander          │
                                                                        │  Management plane       │
                                                                        │  Private: 10.0.1.20    │
                                                                        └─────────────────────────┘
```

### Key Properties
- **Zero code changes** to the Rust scanner — STLink is transparent at the network layer
- **Scanner connects to `http://127.0.0.5:443`** — STLink intercepts and encrypts
- **Caddy on exitpoint** re-encrypts to HTTPS and forwards to Cloudflare Workers
- **All connections outbound-only** on port 443
- **Backward compatible** — `--use-sealedtunnel` flag is opt-in

## Prerequisites

- Hetzner Cloud account with API token
- Xiid SealedTunnel license (Commander activation code)
- Xiid STLink + Commander installers (provided by Xiid)
- `hcloud` CLI installed locally
- Existing ForgeScan scanner registered in dashboard (API key + scanner ID)

## Step 1: Provision Hetzner Infrastructure

```bash
# Run the provisioning script
./deploy/xiid/hetzner-provision.sh \
  --ssh-key my-key \
  --location fsn1
```

This creates:
- Cloud Network `forgescan-internal` (10.0.1.0/24)
- `forgescan-infra` VM (CX22, $4/mo) — Commander + STLink exitpoint + Caddy
- Firewalls for both VMs (outbound 443 + SSH from admin IP only)

## Step 2: Install Infrastructure (Commander + Exitpoint + Caddy)

```bash
# SSH into the infra VM
ssh root@<INFRA_VM_IP>

# Upload and run the install script
./deploy/xiid/install-infra.sh \
  --commander-activation <XIID_ACTIVATION_CODE> \
  --connector-fleet-url <XIID_CONNECTOR_URL> \
  --admin-ip <YOUR_IP>
```

This installs:
1. **Xiid Commander** — management plane, binds to private IP 10.0.1.20
2. **STLink** — exitpoint mode, receives tunnel traffic
3. **Caddy** — reverse proxy from STLink loopback to Cloudflare Workers API

## Step 3: Configure Tunnel Mappings

In the Xiid Commander portal (accessible via SealedTunnel from your workstation):

### External Scanner Tunnel
| Setting | Value |
|---------|-------|
| Tunnel Name | `fs-ext-to-platform` |
| Client Loopback | `127.0.0.5:443` |
| Server Loopback | `127.0.0.1:8443` |
| Client Host | forgescan-scanner-ext |
| Server Host | forgescan-infra |

### On-Prem Scanner Tunnel
| Setting | Value |
|---------|-------|
| Tunnel Name | `fs-onprem-to-platform` |
| Client Loopback | `127.0.0.5:443` |
| Server Loopback | `127.0.0.1:8444` |
| Client Host | Customer on-prem machine |
| Server Host | forgescan-infra |

Generate STLink activation codes for each scanner endpoint.

## Step 4: Install STLink on Scanner

### Hetzner External Scanner

```bash
ssh root@<SCANNER_VM_IP>

# Install STLink + reconfigure scanner for SealedTunnel
./deploy/hetzner/install.sh \
  --api-key <SCANNER_API_KEY> \
  --scanner-id <SCANNER_ID> \
  --use-sealedtunnel \
  --stlink-config /path/to/stlink-config.json
```

### On-Prem Linux Scanner

```bash
curl -fsSL https://raw.githubusercontent.com/Bjay0727-jay/Forge-Scan/main/deploy/onprem/install.sh | \
  sudo bash -s -- \
    --api-key <KEY> \
    --scanner-id <ID> \
    --use-sealedtunnel \
    --stlink-config /path/to/stlink-config.json
```

### On-Prem Windows Scanner

```powershell
.\install-windows.ps1 -ApiKey "sk_scanner_xxx" -ScannerId "scan_xxx" `
  -UseSealedTunnel -StLinkConfigPath "C:\path\to\stlink-config.json"
```

## Step 5: Verify

```bash
# On scanner VM — test tunnel connectivity
curl -v http://127.0.0.5:443/api/v1/scanner/heartbeat \
  -H "X-Scanner-Key: <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"scanner_id":"test","hostname":"test","version":"0.1.0","capabilities":["network"],"active_task_ids":[]}'
# Should return 200 OK

# Check all services
systemctl status stlink forgescan-scanner

# On infra VM
systemctl status xiid-commander stlink caddy

# One-shot scan test through tunnel
forgescan-scanner --one-shot --target 93.184.216.34 --scan-type network \
  --platform http://127.0.0.5:443
```

## Step 6: Lockdown

After verifying everything works:

```bash
# Remove SSH inbound access (manage via SealedTunnel only)
hcloud firewall delete-rule forgescan-scanner-fw --direction in --protocol tcp --port 22
hcloud firewall delete-rule forgescan-infra-fw --direction in --protocol tcp --port 22

# Verify zero inbound ports
nmap -sS <SCANNER_PUBLIC_IP>    # All ports filtered
nmap -sS <INFRA_PUBLIC_IP>      # All ports filtered
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scanner can't reach `127.0.0.5:443` | STLink not running | `systemctl start stlink` |
| Heartbeat returns connection refused | Caddy not running on infra | `systemctl start caddy` on infra VM |
| Heartbeat returns 502 | Caddy can't reach Cloudflare | Check outbound 443 on infra VM |
| STLink won't start | Invalid activation code | Re-generate in Commander portal |
| Commander unreachable | Bound to wrong IP | Check `--bind 10.0.1.20` in Commander config |

## Cost Summary

| Component | Monthly Cost |
|-----------|-------------|
| Scanner VM (CX22, existing) | ~$4 |
| Infra VM (CX22, new) | ~$4 |
| Hetzner Cloud Network | $0 |
| Hetzner Cloud Firewall | $0 |
| **Total Hetzner** | **~$8** |
| Xiid SealedTunnel license | Per Xiid agreement |
