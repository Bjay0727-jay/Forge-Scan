# ForgeScan 360 Deployment Runbook

**Version:** v0.1.0
**Audience:** System administrators deploying ForgeScan in a customer network
**Time estimate:** 30-60 minutes for initial deployment

---

## Prerequisites

| Requirement | Details |
|---|---|
| **OS** | Ubuntu 22.04+, Debian 12+, RHEL 9+, or any Linux with glibc 2.31+ |
| **CPU/RAM** | 2 vCPU, 4 GB RAM minimum (4 vCPU, 8 GB recommended) |
| **Disk** | 2 GB for binary + NVD database |
| **Network** | Outbound HTTPS to `services.nvd.nist.gov` and `www.cisa.gov` for CVE/KEV updates |
| **Privileges** | `CAP_NET_RAW` and `CAP_NET_ADMIN` for raw packet scanning (or run as root) |
| **Docker** (optional) | Docker 24+ for containerized deployment |

---

## Step 1: Download the Scanner Binary

```bash
# Download latest release
curl -LO https://github.com/Bjay0727-jay/Forge-Scan/releases/latest/download/forgescan-scanner-linux-amd64.tar.gz

# Verify checksum (if provided)
sha256sum forgescan-scanner-linux-amd64.tar.gz

# Extract
tar xzf forgescan-scanner-linux-amd64.tar.gz
sudo mv forgescan-scanner /usr/local/bin/
sudo chmod +x /usr/local/bin/forgescan-scanner
```

## Step 2: Create Service User and Directories

```bash
# Create non-root service user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin forgescan

# Create directories
sudo mkdir -p /etc/forgescan
sudo mkdir -p /var/lib/forgescan
sudo mkdir -p /var/log/forgescan

# Set ownership
sudo chown -R forgescan:forgescan /var/lib/forgescan /var/log/forgescan
```

## Step 3: Configure the Scanner

Create `/etc/forgescan/scanner.toml`:

```toml
[scanner]
# Unique scanner identifier (generate with: uuidgen)
scanner_id = "CHANGE-ME-UUID"
max_concurrent_scans = 4
max_concurrent_targets = 50

[platform]
# ForgeScan platform API URL
api_base_url = "https://your-platform.forgescan.com"
# API key (prefer env var FORGESCAN_SCANNER_API_KEY instead)
# api_key = ""
poll_interval_seconds = 30

[nvd]
# NVD API key (get one at https://nvd.nist.gov/developers/request-an-api-key)
# Increases rate limit from 5 req/30s to 50 req/30s
# api_key = ""
database_path = "/var/lib/forgescan/nvd.db"
auto_update = true
update_interval_hours = 24

[logging]
level = "info"
format = "json"
file = "/var/log/forgescan/scanner.log"

[grpc]
# Enable gRPC streaming (optional)
# port = 8443
# tls_cert = "/etc/forgescan/tls/server.crt"
# tls_key = "/etc/forgescan/tls/server.key"
# tls_ca = "/etc/forgescan/tls/ca.crt"
```

## Step 4: Grant Network Capabilities

```bash
# Option A: Set capabilities on binary (preferred over running as root)
sudo setcap 'cap_net_raw,cap_net_admin=eip' /usr/local/bin/forgescan-scanner

# Option B: If using Docker, add to docker run command:
#   --cap-add=NET_RAW --cap-add=NET_ADMIN
```

## Step 5: Initialize NVD Database

```bash
# Run initial NVD sync (may take 30-60 minutes without API key)
sudo -u forgescan forgescan-scanner \
  --one-shot \
  --target 127.0.0.1 \
  --log-level info

# Verify database was created
ls -la /var/lib/forgescan/nvd.db
```

## Step 6: Test with a One-Shot Scan

```bash
# Scan a single known target
sudo -u forgescan forgescan-scanner \
  --one-shot \
  --target 192.168.1.1 \
  --scan-type network \
  --report /tmp/test-report.json \
  --report-format json

# Verify report was generated
cat /tmp/test-report.json | python3 -m json.tool | head -50
```

## Step 7: Create systemd Service

Create `/etc/systemd/system/forgescan-scanner.service`:

```ini
[Unit]
Description=ForgeScan Vulnerability Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=forgescan
Group=forgescan
ExecStart=/usr/local/bin/forgescan-scanner --config /etc/forgescan/scanner.toml
Restart=on-failure
RestartSec=10
StandardOutput=append:/var/log/forgescan/scanner.log
StandardError=append:/var/log/forgescan/scanner.log

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/forgescan /var/log/forgescan
PrivateTmp=yes
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

# Environment
Environment=FORGESCAN_SCANNER_API_KEY=
Environment=FORGESCAN_SCANNER_ID=

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now forgescan-scanner
sudo systemctl status forgescan-scanner
```

## Step 8: Docker Deployment (Alternative)

```bash
docker run -d \
  --name forgescan-scanner \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  --network=host \
  -v /var/lib/forgescan:/var/lib/forgescan \
  -v /etc/forgescan:/etc/forgescan:ro \
  -e FORGESCAN_SCANNER_API_KEY=your-api-key \
  -e FORGESCAN_SCANNER_ID=your-scanner-id \
  ghcr.io/bjay0727-jay/forgescan-scanner:latest
```

## Step 9: Verify Operation

```bash
# Check logs
sudo journalctl -u forgescan-scanner -f

# Verify platform connection (look for "Connected to platform successfully")
sudo journalctl -u forgescan-scanner | grep "heartbeat"

# Check NVD currency
sudo journalctl -u forgescan-scanner | grep "NVD sync"
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "Permission denied" on scan | Missing capabilities | Re-run `setcap` command (Step 4) |
| "Failed to open NVD database" | Directory permissions | `chown forgescan:forgescan /var/lib/forgescan` |
| "NVD API returned status 403" | Rate limited / missing key | Add NVD API key to config |
| Heartbeat failures | Network/firewall | Verify outbound HTTPS to platform URL |
| No findings on scan | NVD database empty | Run NVD sync first (Step 5) |
| gRPC connection refused | Port not open | Check firewall rules for gRPC port |

---

## mTLS Setup (Production)

For production gRPC deployments, generate certificates:

```bash
# Generate CA
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=ForgeScan CA"

# Generate server cert
openssl req -newkey rsa:4096 -nodes -keyout server.key \
  -out server.csr -subj "/CN=forgescan-scanner"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365

# Generate client cert (for platform)
openssl req -newkey rsa:4096 -nodes -keyout client.key \
  -out client.csr -subj "/CN=forgescan-platform"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365

# Install
sudo cp ca.crt server.crt server.key /etc/forgescan/tls/
sudo chmod 600 /etc/forgescan/tls/server.key
```

Then enable in `scanner.toml`:
```toml
[grpc]
port = 8443
tls_cert = "/etc/forgescan/tls/server.crt"
tls_key = "/etc/forgescan/tls/server.key"
tls_ca = "/etc/forgescan/tls/ca.crt"
```
