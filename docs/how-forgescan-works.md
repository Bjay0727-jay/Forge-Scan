# How ForgeScan Works

ForgeScan is an enterprise vulnerability management platform built by Forge Cyber Defense. It combines a cloud-native API on Cloudflare's edge network with distributed Rust-based scanner agents deployed on-premises, in the cloud, or behind zero-trust tunnels. The platform discovers assets, scans for vulnerabilities, scores risk, maps findings to compliance frameworks, and automates response — all from a single dashboard.

What makes ForgeScan different:

- **Hybrid scanning** — cloud API orchestrates scanners that run wherever your assets live (internal networks, DMZs, public cloud)
- **Integrated product suite** — vulnerability management (ForgeScan), SOC detection (ForgeSOC), AI red teaming (ForgeRedOps), and ML correlation (ForgeML) share a single data model and event bus
- **Edge-first architecture** — API runs on Cloudflare Workers with D1/R2/KV storage, eliminating traditional infrastructure management
- **Rust scanner engine** — 13-crate modular scanner with local NVD database, capable of air-gapped operation

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Scanning Pipeline](#2-scanning-pipeline)
3. [Forge Risk Score (FRS)](#3-forge-risk-score-frs)
4. [Event Bus and Cross-Product Integration](#4-event-bus-and-cross-product-integration)
5. [ForgeSOC — Detection and Incident Response](#5-forgesoc--detection-and-incident-response)
6. [ForgeRedOps — AI Red Team](#6-forgeredops--ai-red-team)
7. [Compliance Engine](#7-compliance-engine)
8. [SOAR — Automated Playbooks](#8-soar--automated-playbooks)
9. [Threat Intelligence](#9-threat-intelligence)
10. [Deployment Models](#10-deployment-models)
11. [Dashboard and User Experience](#11-dashboard-and-user-experience)
12. [Security Properties](#12-security-properties)
13. [End-to-End Data Flow](#13-end-to-end-data-flow)

---

## 1. Architecture Overview

ForgeScan is a three-tier system: a React dashboard on the presentation layer, a Hono.js API on Cloudflare Workers at the application layer, and Rust scanner agents at the scanning layer.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PRESENTATION TIER                               │
│                                                                         │
│   React SPA (Cloudflare Pages)                                          │
│   ├── Tailwind CSS + Radix UI components                                │
│   ├── 20+ feature pages (Dashboard, Assets, Findings, SOC, RedOps...)   │
│   ├── Role-based access control (5 roles)                               │
│   └── Real-time polling for active scans and alerts                     │
│                                                                         │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ HTTPS (REST API)
┌───────────────────────────────▼─────────────────────────────────────────┐
│                         APPLICATION TIER                                 │
│                                                                         │
│   Hono.js on Cloudflare Workers (edge, anycast, zero cold start)        │
│   ├── 121 REST endpoints across 22 route modules                        │
│   ├── JWT auth for users, X-Scanner-Key auth for scanners               │
│   ├── Event bus (pub/sub) connecting all subsystems                     │
│   │                                                                     │
│   ├── Storage:                                                          │
│   │   ├── D1 (SQLite) — findings, assets, scans, compliance, events     │
│   │   ├── R2 (S3-compatible) — PDF reports, CSV exports, scan logs      │
│   │   └── KV — session cache, NVD metadata, rate limiting               │
│   │                                                                     │
│   └── Services:                                                         │
│       ├── Scan Orchestrator — creates tasks, assigns to scanners        │
│       ├── ForgeSOC — detection rules, alerts, incidents                  │
│       ├── ForgeML — anomaly detection, clustering, confidence scoring   │
│       ├── ForgeRedOps — AI red team campaigns via Claude API            │
│       ├── Compliance Engine — NIST, CIS, PCI-DSS, HIPAA, CMMC          │
│       ├── SOAR — automated playbooks and response actions               │
│       ├── Threat Intel — feed ingestion, IOC correlation                │
│       └── Integration Manager — email, webhook, Jira, Slack, SIEM      │
│                                                                         │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ HTTPS 443 (outbound from scanners)
┌───────────────────────────────▼─────────────────────────────────────────┐
│                          SCANNING TIER                                   │
│                                                                         │
│   Rust Scanner Engine (13 crates)                                        │
│   ├── forgescan-scanner — agentless network scanner binary               │
│   ├── forgescan-agent — lightweight endpoint agent binary                │
│   │                                                                     │
│   ├── Core crates:                                                      │
│   │   ├── forgescan-core — types, traits, severity, findings            │
│   │   ├── forgescan-common — config, logging, crypto                    │
│   │   ├── forgescan-transport — REST client for API communication       │
│   │   └── forgescan-checks — YAML check registry with 200+ definitions │
│   │                                                                     │
│   ├── Scanning crates:                                                  │
│   │   ├── forgescan-network — host discovery, port scan, service detect │
│   │   ├── forgescan-vuln — CVE detection, version matching, FRS calc    │
│   │   ├── forgescan-nvd — local NVD/CISA KEV database (SQLite)          │
│   │   ├── forgescan-webapp — OWASP Top 10 web scanning                  │
│   │   ├── forgescan-cloud — AWS/Azure/GCP misconfiguration checks       │
│   │   └── forgescan-config-audit — CIS/STIG compliance auditing        │
│   │                                                                     │
│   └── Ingestion:                                                        │
│       └── forgescan-ingest — Nessus/Qualys/Rapid7 result normalization │
│                                                                         │
│   Deployment options:                                                   │
│   ├── On-premises (Linux/Windows binary, systemd service)               │
│   ├── Cloud VM (Docker container on Hetzner, $4/mo)                     │
│   ├── Kubernetes (Helm chart, auto-scaling)                             │
│   └── Xiid SealedTunnel (zero-inbound-port, quantum-resistant)          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Technology Choices

| Component | Technology | Why |
|-----------|-----------|-----|
| API runtime | Cloudflare Workers + Hono.js | Edge deployment, zero cold start, global anycast |
| Primary database | Cloudflare D1 (SQLite) | Distributed edge database, no connection pooling needed |
| Object storage | Cloudflare R2 | S3-compatible, zero egress fees |
| Cache | Cloudflare KV | Global key-value store for sessions and metadata |
| Scanner engine | Rust | Memory safety, async concurrency, raw socket access |
| Local CVE database | SQLite via forgescan-nvd | Air-gapped scanning, no external API calls during scans |
| Dashboard | React + Vite + Tailwind | Fast builds, component library, responsive design |
| AI integration | Claude API (Anthropic) | RedOps agent reasoning, test plan generation |

---

## 2. Scanning Pipeline

The scanning pipeline is the core loop that drives vulnerability discovery. It follows a pull-based architecture: the API creates scan tasks, and scanner agents poll for work.

### Step-by-Step Flow

```
┌──────────┐     ┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│  User    │     │   API        │     │  Scanner Agent   │     │  Database    │
│ (Dashboard)    │ (Workers)    │     │  (Rust binary)   │     │  (D1)        │
└────┬─────┘     └──────┬───────┘     └────────┬────────┘     └──────┬───────┘
     │                  │                       │                     │
     │  1. Create Scan  │                       │                     │
     ├─────────────────►│                       │                     │
     │                  │  2. INSERT scan +     │                     │
     │                  │     scanner_tasks      │                     │
     │                  ├─────────────────────────────────────────────►│
     │                  │                       │                     │
     │                  │  3. Poll for tasks    │                     │
     │                  │◄──────────────────────┤  (every 10 sec)     │
     │                  │                       │                     │
     │                  │  4. Return ApiTask    │                     │
     │                  ├──────────────────────►│                     │
     │                  │                       │                     │
     │                  │                       │  5. Execute scan    │
     │                  │                       │  ├─ Host discovery  │
     │                  │                       │  ├─ Port scanning   │
     │                  │                       │  ├─ Service detect  │
     │                  │                       │  ├─ CVE matching    │
     │                  │                       │  └─ FRS calculation │
     │                  │                       │                     │
     │                  │  6. Submit results    │                     │
     │                  │◄──────────────────────┤                     │
     │                  │                       │                     │
     │                  │  7. Store findings +  │                     │
     │                  │     fire events        │                     │
     │                  ├─────────────────────────────────────────────►│
     │                  │                       │                     │
     │  8. Dashboard    │                       │                     │
     │     updates      │                       │                     │
     │◄─────────────────┤                       │                     │
```

### Scanner Registration

Before a scanner can receive tasks, it must be registered:

1. **Admin registers scanner** in the dashboard — the API issues a `SCANNER_API_KEY` and `SCANNER_ID`
2. **Scanner is deployed** with those credentials (via environment variables or config file at `/etc/forgescan/scanner.toml`)
3. **Scanner starts heartbeat loop** — sends `POST /api/v1/scanner/heartbeat` every 120 seconds with its hostname, version, and capabilities (e.g., `["network", "vulnerability", "webapp", "discovery", "cloud"]`)
4. **Scanner enters task polling loop** — every 10 seconds, calls `GET /api/v1/scanner/tasks/next` with header `X-Scanner-Key`

### Scan Types

| Type | What it does | Engine crate |
|------|-------------|-------------|
| **Network Discovery** | ARP/ICMP/TCP SYN probes to find live hosts | `forgescan-network` |
| **Port Scanning** | SYN/connect/UDP scanning of discovered hosts | `forgescan-network` |
| **Service Detection** | Banner grabbing, protocol identification, OS fingerprinting | `forgescan-network` |
| **Vulnerability Matching** | CPE-based version matching against local NVD database | `forgescan-vuln` + `forgescan-nvd` |
| **Web Application** | OWASP Top 10 testing (SQLi, XSS, CSRF, broken auth) | `forgescan-webapp` |
| **Cloud Misconfiguration** | AWS/Azure/GCP IAM, S3, security group checks | `forgescan-cloud` |
| **Configuration Audit** | CIS Benchmark and STIG compliance checks | `forgescan-config-audit` |
| **Container Scanning** | Image vulnerability analysis for Docker/OCI images | Via API routes |
| **SAST (Code Scan)** | Static analysis for code-level vulnerabilities | Via API routes |

### Check Definitions

Each vulnerability or configuration check is defined in YAML:

```yaml
id: "FSC-VULN-0001"
name: "Apache Log4j Remote Code Execution (Log4Shell)"
category: vulnerability
severity: critical
cve_ids: [CVE-2021-44228, CVE-2021-45046]
cwe_ids: [CWE-502, CWE-400]
compliance:
  - framework: "NIST-800-53"
    control: "SI-2"
  - framework: "PCI-DSS"
    control: "6.2"
detection:
  type: version-match
  cpe: "cpe:2.3:a:apache:log4j:*"
  affected_versions:
    - ">= 2.0-beta9"
    - "< 2.17.0"
remediation: "Upgrade to Log4j 2.17.1 or later"
enabled_by_default: true
```

The scanner loads these definitions from a check registry at startup and uses them during vulnerability matching.

---

## 3. Forge Risk Score (FRS)

ForgeScan calculates a proprietary **Forge Risk Score (FRS)** for each finding, going beyond raw CVSS to account for real-world threat context:

```
FRS = CVSS Base Score
    x Exploit Maturity     (1.0 = unproven, 1.5 = functional, 2.0 = high)
    x Threat Intelligence  (1.0 = no active exploits, 2.0 = widespread in-the-wild)
    x Asset Criticality    (1.0 = low-value asset, 2.0 = crown jewels)
    x Exposure Factor      (1.0 = internal only, 2.0 = internet-facing)
    x Age Factor           (1.0 = old finding, 1.5 = discovered this week)

Final score: 0-100 (normalized)
```

FRS drives prioritization across the platform: dashboard risk grades, SLA deadlines, alert severity, and compliance gap urgency all reference FRS rather than raw CVSS.

---

## 4. Event Bus and Cross-Product Integration

All ForgeScan subsystems communicate through a lightweight pub/sub event bus. When something happens (a vulnerability is detected, a scan completes, a RedOps campaign runs), an event is published. Subscribed handlers react automatically.

### How It Works

1. **Events are published** to the `forge_events` table in D1 with a type, payload, and metadata
2. **Subscriptions** are matched against event types using pattern matching (wildcards supported)
3. **Handlers** execute: create alerts, fire webhooks, send notifications, trigger playbooks

### Event Types

| Event | Published when | Consumed by |
|-------|---------------|-------------|
| `forge.asset.discovered` | New host found during scanning | Asset inventory, ForgeSOC |
| `forge.vulnerability.detected` | Finding created or updated | ForgeSOC, compliance mapping, notifications |
| `forge.scan.completed` | Scan task finishes | Dashboard refresh, report generation |
| `forge.redops.finding` | RedOps agent discovers issue | ForgeSOC, findings table |
| `forge.redops.campaign_complete` | All RedOps agents finish | Notifications, reporting |
| `forge.threat_intel.match` | IOC matches an asset or finding | ForgeSOC alerts, SOAR playbooks |
| `forge.compliance.control_failed` | Finding violates a framework control | Compliance dashboard, POA&M |
| `forge.soc.alert_created` | Detection rule fires | ForgeML clustering, notifications |
| `forge.soc.incident_created` | Alert escalated to incident | SOAR playbooks, PagerDuty |

### Subscription Conditions

Subscriptions can filter events using conditions:

```json
{
  "event_pattern": "forge.vulnerability.detected",
  "conditions": {
    "severity": ["critical", "high"],
    "cvss_score": { "gte": 7.0 }
  },
  "handler": "notification_dispatch",
  "config": { "channels": ["slack", "email"] }
}
```

---

## 5. ForgeSOC — Detection and Incident Response

ForgeSOC is the security operations center module. It watches the event bus, applies detection rules, creates alerts, and manages incidents through their full lifecycle.

### Detection Rules

Detection rules define patterns to watch for. Each rule has:
- **Conditions** — event type, severity, CVSS threshold, asset tags
- **MITRE ATT&CK mapping** — tactic and technique IDs
- **Confidence score** — how certain the rule is about the detection (0-100)
- **Actions** — create alert, escalate to incident, trigger playbook

When an event matches a rule, an alert is created in the `soc_alerts` table with severity, confidence, and MITRE mapping.

### ForgeML — Machine Learning Correlation

ForgeML provides three automated analysis capabilities:

| Capability | Method | Purpose |
|-----------|--------|---------|
| **Anomaly detection** | Z-score analysis on event frequency | Detects unusual spikes in vulnerability discovery or scanning activity |
| **Alert clustering** | Similarity scoring on alert attributes | Groups related alerts into a single incident (reduces noise) |
| **Confidence scoring** | Multi-factor scoring model | Ranks alerts by likelihood of being true positives |

ForgeML runs automatically on new alerts and events. When anomalies are detected or clusters form, it can auto-escalate to incidents.

### Incident Lifecycle

```
new → triaged → investigating → escalated → resolved → closed
```

Each state transition is logged. Incidents track:
- Related alerts (1:N)
- Affected assets
- Timeline of events
- Assigned analyst
- Resolution notes

---

## 6. ForgeRedOps — AI Red Team

ForgeRedOps runs AI-powered offensive security assessments against your infrastructure. It uses Claude (Anthropic's API) to reason about targets, generate test plans, analyze responses, and produce findings.

### Campaign Model

1. **User creates a campaign** — selects targets (IPs, domains, CIDRs) and agent categories
2. **Agents execute in parallel** — each agent type focuses on a specific attack surface
3. **AI generates test plans** — Claude analyzes the target and creates a structured plan
4. **Tests execute** — the agent makes real (safe) requests and analyzes responses
5. **Findings auto-feed into ForgeSOC** — via the event bus, just like scanner findings

### Agent Types

| Agent | Focus Area |
|-------|-----------|
| `web-misconfig` | Security headers, CORS, directory listing, server info leakage |
| `api-auth-bypass` | Authentication flaws, token validation, privilege escalation |
| `cloud-iam` | IAM policy misconfigurations, over-permissive roles |
| `net-ssl-tls` | Certificate issues, weak ciphers, protocol downgrade |
| `net-segmentation` | Network isolation validation, lateral movement paths |
| `net-dns-security` | DNS security assessment, zone transfer, DNSSEC |
| `id-credential` | Default credentials, SSH key auth enforcement, password policy |
| `web-injection` | SQL injection, command injection, template injection |

### Exploitation Levels

Campaigns are configured with an exploitation level that controls how aggressive agents are:

| Level | Behavior |
|-------|---------|
| `passive` | Read-only reconnaissance, no active testing |
| `safe` | Active testing but no exploitation (default) |
| `moderate` | Limited exploitation to confirm vulnerabilities |
| `aggressive` | Full exploitation including payload delivery |

### AI Integration

Each agent uses a `ForgeAIProvider` to interact with Claude:
- **Token budget** — 200K tokens per campaign (configurable)
- **Structured output** — agents receive JSON-formatted test plans and produce structured findings
- **Evidence chain** — every finding includes the AI reasoning, request/response pairs, and remediation advice

---

## 7. Compliance Engine

ForgeScan maps every vulnerability finding to industry compliance frameworks, enabling continuous compliance monitoring.

### Pre-Seeded Frameworks

| Framework | Controls | Description |
|-----------|----------|------------|
| NIST 800-53 Rev. 5 | 25+ families | Federal information security controls |
| CIS Controls v8 | 15+ controls | Prioritized security best practices |
| PCI DSS v4.0 | 12+ requirements | Payment card data protection |
| HIPAA Security Rule | 10+ safeguards | Healthcare data protection |
| CMMC | Multi-level | Cybersecurity maturity for defense contractors |

### How Mapping Works

1. **Check definitions** include compliance references (e.g., `NIST-800-53: SI-2`)
2. When a finding is created, the API **maps it to relevant controls** via those references
3. The compliance dashboard shows **per-framework scoring** — percentage of controls that are compliant, non-compliant, partial, or not assessed
4. **Gap analysis** highlights which controls are failing and why
5. **POA&M entries** (Plan of Action and Milestones) are auto-generated for non-compliant controls with remediation deadlines based on severity

### Compliance Scoring

```
Compliance % = (Compliant Controls / Total Assessed Controls) x 100

Control Status:
  compliant      — all mapped findings are resolved
  non_compliant  — at least one open critical/high finding
  partial        — only medium/low findings remain open
  not_assessed   — no scans have covered this control yet
```

---

## 8. SOAR — Automated Playbooks

The Security Orchestration, Automation, and Response (SOAR) module allows automated incident response through playbooks.

### Playbook Structure

A playbook is a sequence of actions triggered by an event or manually by an analyst:

```
Trigger (event type + conditions)
  └── Step 1: Enrich IOC (lookup threat intel feeds)
  └── Step 2: Block IP (firewall rule via integration)
  └── Step 3: Isolate Host (network quarantine)
  └── Step 4: Create Ticket (Jira/ServiceNow)
  └── Step 5: Send Notification (Slack + PagerDuty)
```

### Available Action Types

| Action | What it does |
|--------|-------------|
| `isolate_host` | Network quarantine of compromised asset |
| `block_ip` | Add IP to firewall blocklist |
| `disable_user` | Disable compromised user account |
| `send_notification` | Slack, Teams, PagerDuty, email alert |
| `create_ticket` | Create Jira/ServiceNow issue |
| `run_scan` | Trigger follow-up vulnerability scan |
| `enrich_ioc` | Look up IOC in threat intel feeds |
| `update_finding` | Change finding status or priority |
| `add_to_blocklist` | Add indicator to internal blocklist |
| `snapshot_evidence` | Capture forensic evidence |
| `escalate_incident` | Promote alert to incident |
| `close_incident` | Resolve and close incident |
| `custom_webhook` | Call arbitrary external API |

### Built-In Templates

ForgeScan ships with 5 playbook templates:
1. **Critical Vulnerability Response** — auto-escalate, notify, create ticket
2. **Active Exploitation Containment** — isolate host, block IP, preserve evidence
3. **Threat Intel Match** — enrich IOC, scan related assets, create alert
4. **Compliance Violation** — create POA&M, notify compliance team
5. **RedOps Finding Triage** — correlate with existing findings, deduplicate

---

## 9. Threat Intelligence

ForgeScan ingests threat intelligence feeds and correlates indicators of compromise (IOCs) against your asset inventory and findings.

### Feed Management

| Feed | Type | Update Frequency |
|------|------|-----------------|
| CISA Known Exploited Vulnerabilities (KEV) | CVE list | Daily |
| Abuse.ch URLhaus | Malicious URLs | Hourly |
| Abuse.ch ThreatFox | IOCs (IPs, domains, hashes) | Hourly |
| AlienVault OTX | Multi-type intelligence | Configurable |
| Emerging Threats | Network signatures | Daily |
| PhishTank | Phishing URLs | Hourly |
| Tor Exit Nodes | IP addresses | Daily |
| Spamhaus DROP | IP blocklists | Daily |

Custom feeds can be added via URL (STIX/TAXII, CSV, JSON formats).

### Correlation Engine

The correlation engine matches ingested indicators against three data sources:

| Indicator Type | Matched Against | Example |
|---------------|----------------|---------|
| CVE ID | Findings table | "CVE-2024-1234 is in CISA KEV and you have 3 unpatched instances" |
| IP address | Asset IP addresses | "Asset 10.0.1.50 matches a known C2 server" |
| Domain / FQDN | Asset FQDNs | "asset.example.com resolves to a known malicious IP" |
| File hash | Endpoint agent file inventory | "SHA256 hash matches known malware sample" |

Each match produces a correlation with a **confidence score** based on feed reliability, indicator age, and match specificity.

---

## 10. Deployment Models

ForgeScan supports four deployment models for scanner agents. The API and dashboard always run on Cloudflare's edge network.

### Model A: On-Premises Scanner

For scanning internal RFC1918 networks.

```
┌────────────────────────────────────────┐
│  Customer Network (DMZ or Internal)    │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │  forgescan-scanner (binary)      │  │
│  │  ├── Runs as systemd service     │  │
│  │  ├── Non-root 'forgescan' user   │  │
│  │  ├── Config: /etc/forgescan/     │  │
│  │  ├── NVD cache: /var/lib/forge.. │  │
│  │  └── Outbound HTTPS 443 only     │  │
│  └──────────────┬───────────────────┘  │
│                 │                       │
└─────────────────┼───────────────────────┘
                  │ HTTPS 443 (outbound)
                  ▼
         Cloudflare Workers API
```

**Install:** `deploy/onprem/install.sh` (Linux) or `deploy/onprem/install-windows.ps1` (Windows)

Supports Ubuntu/Debian, RHEL/Rocky, and Windows Server. Detects architecture (x86_64 or ARM64), downloads the binary, creates the systemd service, and configures credentials.

### Model B: External Cloud Scanner

For scanning public-facing targets from a cloud VM.

```
┌────────────────────────────────────────┐
│  Hetzner CX22 VM (~$4/month)          │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │  Docker container                │  │
│  │  ├── --network host              │  │
│  │  ├── --cap-add NET_RAW           │  │
│  │  ├── --cap-add NET_ADMIN         │  │
│  │  └── ghcr.io/forgescan-scanner   │  │
│  └──────────────┬───────────────────┘  │
│                 │                       │
└─────────────────┼───────────────────────┘
                  │ HTTPS 443 (outbound)
                  ▼
         Cloudflare Workers API
```

**Install:** `deploy/hetzner/install.sh`

Runs the scanner as a Docker container with host networking and raw socket capabilities for SYN scanning.

### Model C: Kubernetes (Helm)

For large-scale deployments with auto-scaling.

```
deploy/helm/forgescan/
├── Chart.yaml
├── values.yaml
└── templates/
    ├── api-deployment.yaml       (2-10 replicas)
    ├── scanner-deployment.yaml   (3-20 replicas, NET_RAW/NET_ADMIN)
    ├── configmap.yaml            (check definitions)
    ├── secret.yaml               (API keys, credentials)
    ├── ingress.yaml              (NGINX ingress)
    └── serviceaccount.yaml       (RBAC)
```

Supports separate scanner pools for network, webapp, and cloud scanning with independent auto-scaling policies. Pod Disruption Budgets ensure availability during updates.

### Model D: Xiid SealedTunnel (Zero-Trust)

For environments requiring zero inbound ports and quantum-resistant encryption.

```
┌─────────────────┐     ┌──────────────────┐     ┌───────────────────┐
│  Scanner VM     │     │  Xiid Connector  │     │  Infra VM         │
│                 │     │  Fleet (SaaS)    │     │  (Hetzner CX22)   │
│  Scanner binary │     │                  │     │                   │
│       │         │     │  Triple-encrypted│     │  STLink Exitpoint │
│  STLink Client  ├────►│  tunnel backbone ├────►│       │           │
│  127.0.0.5:443  │     │                  │     │  Caddy Proxy      │
│                 │     │  Auto-failover   │     │       │           │
│  Outbound only  │     │  Load balancing  │     │  Cloudflare API   │
└─────────────────┘     └──────────────────┘     └───────────────────┘
```

The scanner connects to a local STLink client on `127.0.0.5:443`. STLink encrypts the traffic with quantum-resistant ciphers and routes it through the Xiid Connector Fleet to an exitpoint on the infrastructure VM. A Caddy reverse proxy on the infra VM forwards to the Cloudflare Workers API.

**Result:** Scanner has zero inbound ports, all traffic is encrypted end-to-end, and the infrastructure VM has no public-facing services.

---

## 11. Dashboard and User Experience

The ForgeScan dashboard is a React single-page application deployed on Cloudflare Pages.

### Feature Pages

| Page | Purpose |
|------|---------|
| **Executive Dashboard** | Risk grade (A-F), MTTR, SLA compliance, severity breakdown, posture trends |
| **Assets** | Discovered hosts with IPs, OS, services, open findings count |
| **Findings** | Vulnerability list with CVSS, FRS, state management, bulk actions |
| **Scans** | Create/monitor scans, view progress, review results |
| **RedOps** | Create campaigns, select agents, view AI-generated findings |
| **ForgeSOC** | Alerts, incidents, detection rules, ForgeML overview |
| **Vulnerabilities** | CVE database browser with NVD details |
| **Compliance** | Framework scores, control mapping, gap analysis, POA&M |
| **Playbooks** | SOAR playbook management and execution history |
| **Threat Intel** | Feed management, IOC browser, correlation results |
| **Containers** | Container image vulnerability scanning |
| **Code Scan** | SAST results and code-level findings |
| **Integrations** | Email, webhook, Jira, Slack, SIEM configuration |
| **Notifications** | Notification history and preferences |
| **Reports** | PDF/CSV/JSON report generation (executive, findings, compliance, assets) |
| **Import** | Upload Nessus, Qualys, Rapid7, SARIF, CycloneDX, CSV files |
| **Getting Started** | 5-step onboarding wizard |
| **Settings** | Platform configuration |
| **MSSP Portal** | Multi-tenant management, white-label branding |
| **Scanners** | Scanner agent registration and monitoring |
| **Users** | User management and role assignment |

### Role-Based Access Control

| Role | Permissions |
|------|------------|
| `platform_admin` | Full access: users, scanners, MSSP, all features |
| `scan_admin` | Manage scans, scanners, findings, integrations |
| `vuln_manager` | View/manage findings, run scans, generate reports |
| `remediation_owner` | View assigned findings, update status, add notes |
| `auditor` | Read-only access to all data, compliance reports |

### Report Generation

ForgeScan generates four report types as PDFs (via `pdf-lib`):

1. **Executive Summary** — risk score, grade, severity breakdown, top risks, recommendations
2. **Findings Report** — detailed vulnerability list with CVSS, host, CVE, remediation
3. **Compliance Report** — framework overview, compliance percentages, gap analysis
4. **Asset Inventory** — asset list with IPs, OS, type, finding counts

Reports can also be exported as CSV or JSON.

### MSSP Multi-Tenancy

For managed security service providers, ForgeScan supports:
- **Tenant management** — create, configure, and monitor multiple customer environments
- **White-label branding** — custom logo, colors, and company name per tenant
- **Per-tenant data isolation** — all queries filter by `org_id`
- **Tenant overview dashboard** — aggregate risk scores across all managed tenants

---

## 12. Security Properties

### Zero Inbound Ports

All scanner-to-platform communication is outbound-only. Scanners initiate HTTPS connections to the Cloudflare Workers API on port 443. No inbound ports are required on scanner hosts.

### Authentication Isolation

| Actor | Auth Method | Details |
|-------|-----------|---------|
| Dashboard users | JWT (Bearer token) | Issued on login, validated by `authMiddleware` |
| Scanner agents | `X-Scanner-Key` header | SHA-256 hashed API key, independent from user tokens |

Scanner keys cannot access user endpoints and vice versa.

### Privilege Minimization

- Scanner runs as non-root `forgescan` system user
- Only `NET_RAW` and `NET_ADMIN` Linux capabilities are granted (required for SYN scanning)
- All other capabilities are dropped
- Credentials stored in env files with `chmod 600`

### Air-Gapped Operation

ForgeScan can operate without internet connectivity:
- **Local NVD database** — `forgescan-nvd` crate maintains a SQLite copy of the NVD + CISA KEV catalog, synced via delta updates when connectivity is available
- **Offline AI** — supports Ollama + Llama 3 as an alternative to Claude API for RedOps

### Data Isolation

In multi-tenant deployments, every database query includes an `org_id` filter. Scanner results are tagged with `scanner_id` and `tenant_id` at ingestion. Cross-tenant data access is not possible through the API.

---

## 13. End-to-End Data Flow

Here is how a single vulnerability flows through the entire ForgeScan platform — from discovery to remediation.

```
1. DISCOVERY
   Scanner agent runs network scan against 10.0.1.0/24
   ├── Host discovery: finds 10.0.1.50 (Linux, Apache 2.4.49)
   ├── Port scan: 80/tcp open, 443/tcp open, 22/tcp open
   ├── Service detection: Apache httpd 2.4.49, OpenSSH 8.2
   └── CVE matching: CVE-2021-41773 (Apache path traversal, CVSS 7.5)

2. RESULT SUBMISSION
   Scanner POSTs TaskResultsPayload to /api/v1/scanner/tasks/{id}/results
   ├── Finding: title, severity=high, CVE, CVSS=7.5, evidence, remediation
   ├── Asset: hostname, IP, OS, services
   └── FRS calculated: 7.5 x 1.5 (functional exploit) x 1.5 (in KEV) x 1.5 (web server)
       = FRS 73.2

3. DATABASE STORAGE
   API inserts into D1:
   ├── assets table: new asset record for 10.0.1.50
   ├── findings table: new finding with FRS 73.2, state=open
   └── compliance_mappings: links to NIST SI-2, PCI-DSS 6.2

4. EVENT BUS
   API publishes: forge.vulnerability.detected
   ├── Payload: { finding_id, severity: "high", cvss: 7.5, cve: "CVE-2021-41773" }
   └── All subscribed handlers fire:

5. FORGESOC DETECTION
   Detection rule "Critical/High CVE in KEV" matches
   ├── Creates SOC alert with confidence=85
   ├── MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
   └── ForgeML clusters with 2 other Apache findings → creates Incident

6. THREAT INTEL CORRELATION
   CISA KEV feed contains CVE-2021-41773
   ├── Correlation created: finding ↔ KEV indicator
   └── Confidence boosted to 95 (active exploitation confirmed)

7. SOAR PLAYBOOK
   "Critical Vulnerability Response" playbook triggers:
   ├── Step 1: Enrich — confirm CVE details from NVD
   ├── Step 2: Notify — Slack message to #security-ops
   ├── Step 3: Ticket — Jira issue created, assigned to ops team
   └── Step 4: Escalate — PagerDuty alert for on-call engineer

8. COMPLIANCE IMPACT
   Compliance engine recalculates:
   ├── NIST SI-2 (Flaw Remediation): non_compliant
   ├── PCI-DSS 6.2 (Security Patches): non_compliant
   └── POA&M entry created: "Patch Apache 2.4.49 → 2.4.54, deadline: 30 days"

9. DASHBOARD
   Executive Dashboard updates:
   ├── Risk grade: B+ → B (new high-severity finding)
   ├── Open findings: 47 → 48
   ├── MTTR clock starts for this finding
   └── Posture trend chart shows dip

10. REMEDIATION
    Ops team patches Apache to 2.4.54
    ├── Next scan detects version change
    ├── Finding state: open → fixed
    ├── Compliance control: non_compliant → compliant
    ├── POA&M entry: closed
    ├── MTTR recorded: 3.2 days
    └── Risk grade recovers: B → B+
```

---

## Source Code Reference

| Component | Key Files |
|-----------|----------|
| API entry point | `cloudflare/forgescan-api/src/index.ts` |
| Scanner bridge API | `cloudflare/forgescan-api/src/routes/scanner.ts` |
| Scan orchestrator | `cloudflare/forgescan-api/src/services/scan-orchestrator.ts` |
| Event bus | `cloudflare/forgescan-api/src/services/event-bus/index.ts` |
| ForgeSOC alerts | `cloudflare/forgescan-api/src/services/forgesoc/alert-handler.ts` |
| ForgeML correlation | `cloudflare/forgescan-api/src/services/forgesoc/ml-correlation.ts` |
| RedOps controller | `cloudflare/forgescan-api/src/services/redops/controller.ts` |
| Compliance service | `cloudflare/forgescan-api/src/routes/compliance.ts` |
| SOAR playbooks | `cloudflare/forgescan-api/src/routes/soar.ts` |
| Threat intel | `cloudflare/forgescan-api/src/routes/threat-intel.ts` |
| Rust scanner binary | `engine/crates/forgescan-scanner/src/main.rs` |
| REST transport | `engine/crates/forgescan-transport/src/rest_client.rs` |
| NVD database | `engine/crates/forgescan-nvd/src/lib.rs` |
| Vulnerability detection | `engine/crates/forgescan-vuln/src/lib.rs` |
| Network scanning | `engine/crates/forgescan-network/src/lib.rs` |
| Dashboard routing | `cloudflare/forgescan-dashboard/src/App.tsx` |
| Helm chart | `deploy/helm/forgescan/` |
| On-prem installer | `deploy/onprem/install.sh` |
| Xiid SealedTunnel | `deploy/xiid/` |
