# Changelog

All notable changes to ForgeScan 360 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-18

### Added

#### Scanning Engine
- Network scanning: ARP discovery, TCP SYN/connect, UDP, ICMP host discovery
- Port scanning with configurable concurrency and timeout
- Service detection and version fingerprinting via banner grabbing
- Passive network monitoring for non-disruptive asset discovery
- Web application scanning (OWASP Top 10: XSS, SQLi, CSRF, open redirects, header analysis)
- Cloud configuration auditing (AWS EC2, S3, IAM, Inspector2)
- YAML-based vulnerability check definitions with 50+ built-in checks
- Safe-Scan profiles for medical devices and industrial/SCADA equipment

#### Vulnerability Intelligence
- NVD API 2.0 integration with full and incremental CVE sync
- CISA Known Exploited Vulnerabilities (KEV) catalog integration
- CPE 2.3 matching with version range comparison
- NVD auto-update scheduler with daily incremental refresh and currency tracking
- SQLite-backed local CVE database

#### Risk Scoring
- Forge Risk Score (FRS): composite score weighting CVSS (35%), Exploit Maturity (20%), KEV (20%), Network Exposure (15%), Asset Criticality (10%)
- Automatic FRS calculation on all findings

#### Compliance & Reporting
- HIPAA Security Rule mapping (4 Technical Safeguards: Access Control, Audit Controls, Integrity, Transmission Security)
- HCCRA 7-control mapping
- PDF compliance reports: executive summary, safeguard scorecard, HCCRA scorecard, top risks, gap analysis
- JSON compliance report export
- ForgeComply 360 offline JSON export for GRC platform integration

#### gRPC Streaming
- Server-streaming RPC for real-time scan event delivery
- Client library for scan execution, heartbeat, and configuration retrieval
- mTLS support for production gRPC deployments (client certificate verification)
- Proto definitions: common, results, scan_service, agent_service

#### Security Hardening
- Input validation on all scan targets (CIDR prefix limits, hostname RFC 1035, URL injection prevention, IP range bounds)
- Secret scanning in CI pipeline (AWS keys, GitHub tokens, private keys, hardcoded credentials)
- Scanner rejects malformed targets before scanning begins
- Non-root execution with Linux capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`)

#### Deployment & Operations
- Multi-arch release binaries (linux-amd64, linux-arm64, windows-amd64)
- Docker images: scanner (Debian slim) and agent (distroless)
- systemd service file template
- Deployment runbook with step-by-step instructions
- Customer onboarding checklist (network access, firewall rules, scan windows, compliance)

#### Accuracy Validation
- Comparison framework for validating against Nessus/OpenVAS baselines
- Nessus CSV import with normalized finding matching
- Metrics: overlap percentage, false positive rate, missed detections

#### CI/CD
- `cargo fmt`, `cargo clippy`, `cargo test`, `cargo audit` in GitHub Actions
- Secret scanning job in CI pipeline
- Release binary workflow triggered on version tags
- Docker image build workflow

### Infrastructure
- 14-crate Rust workspace architecture
- REST API client for Cloudflare Workers platform backend
- Criterion benchmarks for FRS calculation, HIPAA mapping, report generation
- Release-optimized profiles: `release` (size-optimized) and `release-scanner` (speed-optimized)
