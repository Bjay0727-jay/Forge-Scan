# ForgeScan 360 — Hybrid Scanning Architecture

> Cloudflare Edge + Xiid SealedTunnel + Hetzner External Scanner + On-Prem Internal Scanner

## Overview

ForgeScan 360 uses a **hybrid deployment model** with cloud-hosted management (Cloudflare), distributed scanner nodes, and **Xiid SealedTunnel** for quantum-resistant, zero-inbound-port secure communication between all components.

**Key design principles:**
- **Zero inbound ports** — all connections outbound-only on port 443
- **Xiid SealedTunnel** provides triple-encrypted, quantum-secure transport
- Scanner connects to local STLink loopback (`http://127.0.0.5:443`) — STLink handles encryption
- Caddy exitpoint proxies tunnel traffic to Cloudflare Workers API
- Scanner authentication via `X-Scanner-Key` header (separate from user JWT)
- NVD vulnerability database is **local** to each scanner
- **Zero code changes** to scanner — STLink is transparent at the network layer
- Backward compatible — SealedTunnel is opt-in via `--use-sealedtunnel` flag

## Network Diagram

```mermaid
graph TB
    subgraph Internet["Internet"]
        User["Security Analyst<br/>Browser"]
        ExtTargets["External Targets<br/>Public IPs / Domains"]
    end

    subgraph CF["Cloudflare Edge Network"]
        Pages["Dashboard<br/>Cloudflare Pages<br/>React SPA"]
        Workers["API Server<br/>Cloudflare Workers<br/>Hono + REST"]
        D1["D1 Database"]
        R2["R2 Storage"]
        KV["KV Cache"]
    end

    subgraph XiidInfra["Xiid SealedTunnel Infrastructure"]
        subgraph InfraVM["forgescan-infra - CX22 - $4/mo"]
            Commander["Xiid Commander<br/>Management Plane<br/>Private: 10.0.1.20"]
            STLinkExit["STLink Exitpoint<br/>Receives tunnel traffic<br/>Binds 127.0.0.1:8443-8444"]
            Caddy["Caddy Reverse Proxy<br/>Loopback to HTTPS<br/>Forwards to Workers API"]
        end
        ConnectorFleet["Xiid Connector Fleet<br/>SaaS - Triple Encrypted<br/>Quantum Secure<br/>Auto-Failover"]
    end

    subgraph Hetzner["Hetzner Cloud - Falkenstein DC"]
        HetzScanner["External Scanner<br/>forgescan-scanner<br/>--platform http://127.0.0.5:443<br/>CX22 - 2 vCPU - 4GB"]
        STLinkExt["STLink Client<br/>Binds 127.0.0.5:443"]
        NVD_H["NVD Database<br/>Docker Volume"]
    end

    subgraph CustomerNet["Customer Network - On-Premises"]
        subgraph DMZ["DMZ"]
            OnPremScanner["Internal Scanner<br/>forgescan-scanner<br/>--platform http://127.0.0.5:443"]
            STLinkOnPrem["STLink Client<br/>Binds 127.0.0.5:443"]
            NVD_O["NVD Database"]
        end
        subgraph Internal["Internal Network - RFC1918"]
            IntTargets["Internal Targets<br/>192.168.x.x / 10.x.x.x"]
        end
    end

    subgraph CICD["GitHub"]
        Actions["GitHub Actions<br/>CI/CD"]
        GHCR["GHCR<br/>Container Registry"]
        Releases["GitHub Releases<br/>Static Binaries"]
    end

    %% User flows
    User -->|"HTTPS :443"| Pages
    User -->|"HTTPS :443"| Workers
    Pages -->|"fetch API calls"| Workers

    %% Worker - Storage
    Workers --- D1
    Workers --- R2
    Workers --- KV

    %% Scanner to STLink local
    HetzScanner -->|"http://127.0.0.5:443"| STLinkExt
    OnPremScanner -->|"http://127.0.0.5:443"| STLinkOnPrem

    %% STLink to Connector Fleet outbound 443
    STLinkExt -->|"Outbound :443<br/>Quantum encrypted"| ConnectorFleet
    STLinkOnPrem -->|"Outbound :443<br/>Quantum encrypted"| ConnectorFleet

    %% Connector Fleet to Exitpoint
    ConnectorFleet -->|"Outbound :443"| STLinkExit

    %% Exitpoint to Caddy to Workers
    STLinkExit -->|"127.0.0.1:8443"| Caddy
    Caddy -->|"HTTPS :443<br/>TLS to Cloudflare"| Workers

    %% Scanner to Targets
    HetzScanner -->|"TCP SYN/Connect<br/>Raw sockets"| ExtTargets
    OnPremScanner -->|"TCP SYN/Connect<br/>Raw sockets"| IntTargets

    %% NVD
    HetzScanner --- NVD_H
    OnPremScanner --- NVD_O

    %% CI/CD
    Actions -->|"docker push"| GHCR
    Actions -->|"upload"| Releases
    GHCR -.->|"docker pull"| HetzScanner
    Releases -.->|"binary"| OnPremScanner

    %% Styling
    classDef cloudflare fill:#f48120,color:#fff,stroke:#e0740c
    classDef xiid fill:#dc2626,color:#fff,stroke:#b91c1c
    classDef hetzner fill:#0ea5e9,color:#fff,stroke:#0284c7
    classDef customer fill:#10b981,color:#fff,stroke:#059669
    classDef github fill:#24292e,color:#fff,stroke:#1b1f23
    classDef target fill:#6b7280,color:#fff,stroke:#4b5563

    class Pages,Workers,D1,R2,KV cloudflare
    class Commander,STLinkExit,Caddy,ConnectorFleet xiid
    class HetzScanner,STLinkExt,NVD_H hetzner
    class OnPremScanner,STLinkOnPrem,NVD_O,IntTargets customer
    class Actions,GHCR,Releases github
    class ExtTargets target
```

## Data Flow

1. Scanner starts with `--platform http://127.0.0.5:443`
2. `reqwest` sends `POST http://127.0.0.5:443/api/v1/scanner/heartbeat` (plain HTTP to loopback)
3. STLink intercepts traffic at `127.0.0.5:443`, encrypts (quantum-resistant)
4. STLink sends outbound :443 to Xiid Connector Fleet
5. Connector Fleet routes to exitpoint's STLink on `forgescan-infra` VM
6. STLink exitpoint decrypts, delivers to `127.0.0.1:8443`
7. Caddy receives, re-encrypts with TLS, forwards to `https://forgescan-api.stanley-riley.workers.dev`
8. Workers API processes request, response returns through the same path

**Why HTTP to loopback?** STLink provides encryption. Using HTTPS would be unnecessary double-encryption. The `X-Scanner-Key` header on loopback never leaves the machine.

## Component Details

### Cloudflare Edge (Management Plane)

| Component | Service | Purpose |
|-----------|---------|---------|
| **Workers API** | Hono + REST | Scanner task queue, result ingestion |
| **Pages Dashboard** | React SPA | Security analyst interface |
| **D1** | SQLite | Scans, tasks, findings, assets |
| **R2** | Object Storage | PDF reports, CSV exports |
| **KV** | Key-Value | Sessions, NVD metadata cache |

### Xiid SealedTunnel Infrastructure

| Component | VM | Purpose |
|-----------|-----|---------|
| **Xiid Commander** | forgescan-infra (CX22) | Tunnel management, mapping config, private IP 10.0.1.20 |
| **STLink Exitpoint** | forgescan-infra (CX22) | Receives tunnel traffic, binds 127.0.0.1:8443-8444 |
| **Caddy** | forgescan-infra (CX22) | Reverse proxy: loopback to Cloudflare Workers HTTPS |
| **Connector Fleet** | Xiid SaaS | Triple-encrypted bridge, quantum secure, auto-failover |

### Tunnel Mapping Table

| Tunnel | Scanner Side Bind | Exitpoint Side Bind | Purpose |
|--------|------------------|--------------------|---------|
| `fs-ext-to-platform` | `127.0.0.5:443` on scanner VM | `127.0.0.1:8443` on infra VM | External scanner to API |
| `fs-onprem-to-platform` | `127.0.0.5:443` on customer host | `127.0.0.1:8444` on infra VM | On-prem scanner to API |

### Hetzner Cloud

| VM | Spec | Cost | Role |
|----|------|------|------|
| `forgescan-scanner-ext` | CX22, 2 vCPU, 4 GB, 40 GB | ~$4/mo | Scanner + STLink client |
| `forgescan-infra` | CX22, 2 vCPU, 4 GB, 40 GB | ~$4/mo | Commander + exitpoint + Caddy |
| **Total** | | **~$8/mo** | |

## Security Model

1. **Zero inbound ports** — All connections outbound-only on port 443 (post-lockdown)
2. **Quantum-resistant encryption** — Xiid SealedTunnel triple-encrypted transport
3. **No VPN required** — STLink replaces traditional VPN with zero-trust tunnels
4. **Separate auth** — Scanner API keys (`X-Scanner-Key`) independent of user JWT
5. **Least privilege** — Scanner runs as non-root `forgescan` user with only NET_RAW/NET_ADMIN caps
6. **Credential isolation** — API keys in env files (mode 600) or machine environment variables
7. **NVD locality** — Vulnerability database local to each scanner, no external API calls
8. **Commander isolation** — Management plane bound to private IP (10.0.1.20) on isolated VLAN
9. **Post-lockdown** — After setup, remove SSH access; manage everything through SealedTunnel

## Quick Start

### External Scanner (Hetzner + SealedTunnel)

```bash
./deploy/hetzner/install.sh \
  --api-key <KEY> --scanner-id <ID> \
  --use-sealedtunnel --stlink-config /path/to/stlink.json
```

### Internal Scanner (Linux + SealedTunnel)

```bash
./deploy/onprem/install.sh \
  --api-key <KEY> --scanner-id <ID> \
  --use-sealedtunnel --stlink-config /path/to/stlink.json
```

### Internal Scanner (Windows + SealedTunnel)

```powershell
.\install-windows.ps1 -ApiKey "sk_xxx" -ScannerId "scan_xxx" `
  -UseSealedTunnel -StLinkConfigPath "C:\path\to\stlink.json"
```

### Direct Mode (No SealedTunnel)

```bash
./deploy/hetzner/install.sh --api-key <KEY> --scanner-id <ID>
```
