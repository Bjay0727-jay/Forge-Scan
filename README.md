# ForgeScan 360

Enterprise Vulnerability Management Platform by Forge Cyber Defense.

## Overview

ForgeScan 360 is a comprehensive vulnerability management platform that combines:

- **ForgeScan Engine** - Native Rust-based vulnerability scanner (agentless + agent)
- **ForgeScan 360** - Vulnerability management, asset discovery, risk scoring (FRS)
- **ForgeSOC** - 24/7 threat monitoring, detection, incident response
- **ForgeRedOps** - AI-powered penetration testing (24 autonomous agents)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    FORGE PLATFORM CORE                       │
│  Asset Registry │ Compliance Core │ Integration Hub          │
│  Event Bus │ API Gateway │ UI Shell                          │
└─────────────────────────────────────────────────────────────┘
        │                    │                    │
┌───────┴───────┐  ┌────────┴────────┐  ┌───────┴───────┐
│  ForgeScan    │  │    ForgeSOC     │  │  ForgeRedOps  │
│  360          │  │                 │  │               │
│               │  │  - Detection    │  │  - 24 AI      │
│  - Scanner    │  │  - Incidents    │  │    Agents     │
│  - Discovery  │  │  - Playbooks    │  │  - Pen Test   │
│  - FRS Score  │  │  - ForgeML      │  │  - Exploit    │
└───────────────┘  └─────────────────┘  └───────────────┘
```

## ForgeScan Engine (Rust)

The native scanner engine provides:

### Scan Capabilities
- **Network Discovery** - Host discovery, port scanning, service detection
- **Vulnerability Detection** - CVE matching against NVD database
- **Configuration Auditing** - CIS Benchmarks, DISA STIGs
- **Web Application Scanning** - OWASP Top 10
- **Cloud Misconfiguration** - AWS, Azure, GCP checks

### Deployment Modes
- **Agentless Scanner** - Network-based scanning from central location
- **Endpoint Agent** - Lightweight agent (<10MB) for deep local inspection

### Key Features
- Real-time finding streaming via gRPC
- Offline/air-gapped support with local NVD database
- YAML-based check definitions
- Cross-platform agent (Linux, Windows, macOS)

## Project Structure

```
ForgeScan/
├── engine/                    # Rust scanner engine
│   ├── crates/
│   │   ├── forgescan-core/    # Core types, traits, errors
│   │   ├── forgescan-common/  # Logging, config, crypto
│   │   ├── forgescan-checks/  # Check registry, YAML parser
│   │   ├── forgescan-nvd/     # NVD/CVE database
│   │   ├── forgescan-network/ # Port scanning, service detection
│   │   ├── forgescan-vuln/    # CVE version matching
│   │   ├── forgescan-webapp/  # Web app scanning
│   │   ├── forgescan-cloud/   # Cloud misconfig checks
│   │   ├── forgescan-scanner/ # Agentless scanner binary
│   │   └── forgescan-agent/   # Endpoint agent binary
│   ├── proto/                 # gRPC Protobuf definitions
│   ├── checks/                # YAML check definitions
│   └── config/                # Example configuration files
├── packages/                  # TypeScript platform (future)
│   ├── core/                  # Shared platform modules
│   └── products/              # Product-specific modules
└── docs/                      # Documentation
```

## Building

### Prerequisites
- Rust 1.78+ (for engine)
- Node.js 20+ (for platform - future)

### Build Scanner Engine

```bash
cd engine
cargo build --release

# Binaries located at:
# target/release/forgescan-scanner
# target/release/forgescan-agent
```

### Run Scanner

```bash
# Copy and customize config
cp config/scanner.example.toml /etc/forgescan/scanner.toml

# Run scanner
./target/release/forgescan-scanner --config /etc/forgescan/scanner.toml
```

### Run Agent

```bash
# Register agent with platform
./target/release/forgescan-agent --register --platform https://forge.example.com:8443

# Start agent daemon
./target/release/forgescan-agent
```

## Check Definitions

Checks are defined in YAML format:

```yaml
id: "FSC-VULN-0001"
name: "Apache Log4j RCE (Log4Shell)"
category: vulnerability
severity: critical
cve_ids:
  - CVE-2021-44228
detection:
  type: version-match
  cpe: "cpe:2.3:a:apache:log4j:*"
  affected_versions:
    - ">= 2.0-beta9"
    - "< 2.17.0"
remediation: "Upgrade to Log4j 2.17.1 or later"
```

## License

Proprietary - Forge Cyber Defense

## Contact

- Website: https://forgecyber.com
- Support: support@forgecyber.com
