# ForgeScan 360 — Hybrid Scanning Architecture

> Cloudflare Edge + Hetzner External Scanner + On-Prem Internal Scanner

## Overview

ForgeScan 360 uses a **hybrid deployment model** that combines cloud-hosted management (Cloudflare) with distributed scanner nodes. External scanners run on Hetzner Cloud VPS (~$4/mo), while internal scanners deploy as native binaries or Docker containers inside customer networks.

**Key design principles:**
- All scanner connections are **outbound-only** (HTTPS port 443)
- No VPN, no inbound ports, no firewall rules needed
- Scanner authentication via `X-Scanner-Key` header (separate from user JWT)
- NVD vulnerability database is **local** to each scanner (no runtime API calls)
- Scanners poll the platform for tasks — no push mechanism required

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
        D1["D1 Database<br/>SQLite"]
        R2["R2 Storage<br/>Reports / Exports"]
        KV["KV Cache<br/>Sessions / NVD"]
    end

    subgraph Hetzner["Hetzner Cloud - Falkenstein DC"]
        HetzScanner["External Scanner<br/>forgescan-scanner<br/>Docker + host networking<br/>CX22 - 2 vCPU - 4GB"]
        NVD_H["NVD Database<br/>Docker Volume"]
    end

    subgraph CustomerNet["Customer Network - On-Premises"]
        subgraph DMZ["DMZ"]
            OnPremScanner["Internal Scanner<br/>forgescan-scanner<br/>systemd service or Docker"]
            NVD_O["NVD Database<br/>/var/lib/forgescan"]
        end
        subgraph Internal["Internal Network - RFC1918"]
            IntTargets["Internal Targets<br/>192.168.x.x / 10.x.x.x<br/>Servers - Switches - IoT"]
        end
    end

    subgraph CICD["GitHub"]
        Repo["Forge-Scan Repo"]
        Actions["GitHub Actions"]
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

    %% Scanner - API outbound HTTPS only
    HetzScanner -->|"HTTPS :443<br/>X-Scanner-Key auth<br/>POST /heartbeat<br/>GET /tasks/next<br/>POST /tasks/:id/results"| Workers
    OnPremScanner -->|"HTTPS :443<br/>X-Scanner-Key auth<br/>Outbound only"| Workers

    %% Scanner - Targets
    HetzScanner -->|"TCP SYN/Connect<br/>HTTP/HTTPS<br/>Raw sockets"| ExtTargets
    OnPremScanner -->|"TCP SYN/Connect<br/>HTTP/HTTPS<br/>Raw sockets"| IntTargets

    %% NVD volumes
    HetzScanner --- NVD_H
    OnPremScanner --- NVD_O

    %% CI/CD flows
    Repo -->|"push / tag"| Actions
    Actions -->|"docker push"| GHCR
    Actions -->|"upload artifacts"| Releases
    GHCR -.->|"docker pull"| HetzScanner
    GHCR -.->|"docker pull"| OnPremScanner
    Releases -.->|"binary download"| OnPremScanner

    %% Styling
    classDef cloudflare fill:#f48120,color:#fff,stroke:#e0740c
    classDef hetzner fill:#d50c2d,color:#fff,stroke:#b00a25
    classDef customer fill:#2563eb,color:#fff,stroke:#1d4ed8
    classDef github fill:#24292e,color:#fff,stroke:#1b1f23
    classDef target fill:#6b7280,color:#fff,stroke:#4b5563

    class Pages,Workers,D1,R2,KV cloudflare
    class HetzScanner,NVD_H hetzner
    class OnPremScanner,NVD_O,IntTargets customer
    class Repo,Actions,GHCR,Releases github
    class ExtTargets target
```

## Component Details

### Cloudflare Edge (Management Plane)

| Component | Service | Purpose |
|-----------|---------|---------|
| **Workers API** | Hono + REST | Scanner task queue, result ingestion, auth |
| **Pages Dashboard** | React SPA | Security analyst interface |
| **D1** | SQLite | Scans, tasks, findings, assets |
| **R2** | Object Storage | PDF reports, CSV exports |
| **KV** | Key-Value Cache | Sessions, NVD metadata cache |

**API Endpoints (Scanner-facing):**
- `POST /api/v1/scanners/heartbeat` — Scanner health check + status
- `GET /api/v1/tasks/next` — Poll for next assigned task
- `POST /api/v1/tasks/:id/start` — Mark task as running
- `POST /api/v1/tasks/:id/results` — Submit scan results (findings, assets, ports)
- `POST /api/v1/tasks/:id/failure` — Report task failure

### Hetzner Cloud (External Scanner)

| Spec | Value |
|------|-------|
| **Server** | CX22 (shared) |
| **Cost** | ~$3.99/mo |
| **CPU** | 2 vCPU (AMD EPYC) |
| **RAM** | 4 GB |
| **Disk** | 40 GB NVMe |
| **OS** | Ubuntu 22.04 LTS |
| **Runtime** | Docker + host networking |
| **Capabilities** | NET_RAW, NET_ADMIN |

**Docker run flags:**
```bash
docker run --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v forgescan-nvd:/var/lib/forgescan \
  ghcr.io/bjay0727-jay/forgescan-scanner:latest \
  --platform https://forgescan-api.stanley-riley.workers.dev
```

### Customer On-Premises (Internal Scanner)

| Deployment | Method |
|------------|--------|
| **Linux** | Native binary + systemd service |
| **Linux (Docker)** | Same image as Hetzner, `--network host` |
| **Windows** | Native binary + Windows Service |

**Systemd capabilities (non-root):**
```ini
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
```

### CI/CD Pipeline (GitHub Actions)

| Workflow | Trigger | Output |
|----------|---------|--------|
| **ci.yml** | Pull requests | fmt + clippy + test |
| **build-docker.yml** | Push to main / tags | Multi-arch Docker image → GHCR |
| **release-binaries.yml** | Version tags (v*) | Cross-compiled binaries → GitHub Releases |

**Targets:**
- `x86_64-unknown-linux-gnu` (amd64)
- `aarch64-unknown-linux-gnu` (arm64)
- `x86_64-pc-windows-gnu` (Windows)

## Security Model

1. **No inbound ports** — Scanners only make outbound HTTPS connections
2. **Separate auth** — Scanner API keys (`X-Scanner-Key`) are independent of user JWT tokens
3. **Least privilege** — Scanner runs as non-root `forgescan` user with only NET_RAW/NET_ADMIN caps
4. **Credential isolation** — API keys stored in env files (mode 600) or machine environment variables
5. **NVD locality** — Vulnerability database is local to each scanner; no external NVD API calls during scans
6. **TLS everywhere** — All scanner-to-platform communication is HTTPS with certificate validation

## Quick Start

### External Scanner (Hetzner)

```bash
# On a fresh Hetzner CX22 VPS
curl -fsSL https://raw.githubusercontent.com/Bjay0727-jay/Forge-Scan/main/deploy/hetzner/install.sh | \
  sudo bash -s -- --api-key <KEY> --scanner-id <ID>
```

### Internal Scanner (Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/Bjay0727-jay/Forge-Scan/main/deploy/onprem/install.sh | \
  sudo bash -s -- --api-key <KEY> --scanner-id <ID>
```

### Internal Scanner (Windows)

```powershell
.\install-windows.ps1 -ApiKey "sk_scanner_xxx" -ScannerId "scan_xxx"
```
