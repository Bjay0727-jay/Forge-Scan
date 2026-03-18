# ForgeScan 360 Customer Onboarding Checklist

**Version:** v0.1.0
**Purpose:** Ensure all prerequisites are met before deploying ForgeScan in a customer environment.

---

## 1. Network Access Requirements

- [ ] **Scanner host has IP connectivity** to all target subnets/VLANs that will be scanned
- [ ] **DNS resolution** works from scanner host to target hostnames (if scanning by name)
- [ ] **Outbound HTTPS** allowed from scanner to:
  - `services.nvd.nist.gov` (NVD CVE database updates)
  - `www.cisa.gov` (CISA KEV catalog)
  - ForgeScan platform API URL (if using cloud dashboard)
- [ ] **No IPS/IDS blocking** scan traffic between scanner and targets (or scanner IP whitelisted)
- [ ] **ICMP allowed** from scanner to targets (for host discovery; or use TCP-only discovery)

## 2. Firewall Rules

| Direction | Source | Destination | Port/Proto | Purpose |
|---|---|---|---|---|
| Outbound | Scanner | Targets | TCP 1-65535 | Port scanning |
| Outbound | Scanner | Targets | UDP 53, 161, 443 | DNS, SNMP, service probes |
| Outbound | Scanner | Targets | ICMP | Host discovery |
| Outbound | Scanner | NVD API | TCP 443 | CVE database updates |
| Outbound | Scanner | Platform | TCP 443 | Result upload, heartbeat |
| Inbound | Platform | Scanner | TCP 8443 | gRPC streaming (if enabled) |

## 3. Scan Window Configuration

- [ ] **Scan window agreed** with customer (e.g., nightly 10pm-6am, weekends)
- [ ] **Maintenance window** does NOT overlap with scan window
- [ ] **Critical systems exclusion list** documented (e.g., production databases, life-critical devices)
- [ ] **Medical device inventory** reviewed if healthcare environment
  - Safe-Scan profile assigned to medical/IoT devices
  - Passive-only or lightweight mode for life-critical equipment
- [ ] **Rate limiting** configured if customer network is bandwidth-constrained
  - `max_concurrent_scans` set appropriately
  - `max_concurrent_targets` adjusted for network capacity

## 4. Asset Inventory

- [ ] **Target list** provided by customer:
  - IP ranges / CIDR blocks to scan
  - Web application URLs for webapp scanning
  - Cloud account credentials for cloud configuration audit (if applicable)
- [ ] **Excluded targets** documented:
  - IPs/subnets explicitly excluded from scanning
  - Devices that should NOT receive active probes
- [ ] **Asset criticality** ratings assigned (for Forge Risk Score weighting):
  - Critical: EHR systems, domain controllers, payment systems
  - High: Database servers, application servers
  - Medium: Workstations, printers
  - Low: Development/test systems

## 5. Credentials and Access

- [ ] **Scanner service account** created on target network
- [ ] **NVD API key** obtained (https://nvd.nist.gov/developers/request-an-api-key)
- [ ] **Platform API key** generated for scanner-to-platform communication
- [ ] **Scanner ID** provisioned in ForgeScan platform
- [ ] **mTLS certificates** generated and distributed (if gRPC streaming enabled)
- [ ] **SSH credentials** configured (if authenticated scanning is needed)
- [ ] **SNMP community strings** provided (if SNMP-based discovery enabled)

## 6. Compliance Requirements

- [ ] **Compliance framework** identified:
  - [ ] HIPAA Security Rule (healthcare)
  - [ ] PCI DSS (payment processing)
  - [ ] NIST 800-53 (federal/government)
  - [ ] CIS Controls
- [ ] **Report format** agreed: JSON, PDF, or ForgeComply 360 export
- [ ] **Report delivery** method: local file, platform dashboard, email
- [ ] **Retention period** for scan results defined

## 7. Pre-Deployment Validation

- [ ] **Test scan** executed against a single non-production host
- [ ] **Results reviewed** with customer security team
- [ ] **False positive baseline** established (if comparing with existing scanner)
- [ ] **Network impact assessment** — no disruption during test scan
- [ ] **Scanner performance** acceptable (scan time, CPU/memory usage)

## 8. Go-Live Checklist

- [ ] Scanner deployed per [Deployment Runbook](deployment-runbook.md)
- [ ] NVD database fully synced (initial sync completed)
- [ ] Daemon mode running and heartbeat confirmed
- [ ] First scheduled scan executed successfully
- [ ] Results uploaded to platform and visible in dashboard
- [ ] HIPAA compliance report generated and delivered
- [ ] Customer POC trained on:
  - Reviewing scan results
  - Understanding Forge Risk Scores
  - Accessing compliance reports
  - Scheduling scan windows

## 9. Post-Deployment

- [ ] **Monitoring** configured for scanner process health
- [ ] **Log rotation** set up for `/var/log/forgescan/`
- [ ] **NVD auto-update** verified (daily incremental sync running)
- [ ] **Escalation path** documented for scanner issues
- [ ] **Review cadence** agreed (weekly/monthly finding reviews)
