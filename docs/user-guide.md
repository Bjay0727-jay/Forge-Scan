# ForgeScan Platform User Guide

This guide covers all three products in the Forge Cyber Defense platform: **FC360** (GRC workflows), **Reporter** (SSP authoring and report generation), and **ForgeScan** (vulnerability scanning). Each section provides step-by-step instructions for day-to-day operations.

---

## Table of Contents

1. [FC360 GRC Workflows](#1-fc360-grc-workflows)
   - [Framework Management](#11-framework-management)
   - [Control Mapping and Assessment](#12-control-mapping-and-assessment)
   - [Evidence Collection and Attachment](#13-evidence-collection-and-attachment)
   - [Gap Analysis and Remediation Tracking](#14-gap-analysis-and-remediation-tracking)
   - [POA&M Management](#15-poam-management)
   - [Compliance Reporting](#16-compliance-reporting)
2. [Reporter SSP Authoring](#2-reporter-ssp-authoring)
   - [Generating Reports](#21-generating-reports)
   - [Report Formats](#22-report-formats)
   - [Deep Linking from Compliance Pages](#23-deep-linking-from-compliance-pages)
   - [Vulnerabilities Report with FC360 Control Mappings](#24-vulnerabilities-report-with-fc360-control-mappings)
   - [Downloading and Managing Generated Reports](#25-downloading-and-managing-generated-reports)
3. [ForgeScan Scanning](#3-forgescan-scanning)
   - [Scanner Registration and Management](#31-scanner-registration-and-management)
   - [Agent Registration](#32-agent-registration)
   - [Scan Types](#33-scan-types)
   - [Configuration Auditing](#34-configuration-auditing)
   - [Running Scans and Viewing Results](#35-running-scans-and-viewing-results)
   - [Asset Discovery and Inventory](#36-asset-discovery-and-inventory)
   - [Finding Management and Remediation](#37-finding-management-and-remediation)

---

## 1. FC360 GRC Workflows

FC360 is the Governance, Risk, and Compliance (GRC) module built into ForgeScan. It maps vulnerability findings to industry compliance frameworks, tracks control assessments, collects evidence, and manages Plans of Action and Milestones (POA&M). All GRC data lives in the same database as scan results, so compliance posture updates automatically as findings are discovered and remediated.

### 1.1 Framework Management

FC360 ships with pre-seeded definitions for the following compliance frameworks:

| Framework | Description | Control Families |
|-----------|-------------|-----------------|
| **NIST 800-53 Rev. 5** | Federal information security controls | 25+ families (AC, AU, CM, IA, SI, etc.) |
| **CIS Controls v8** | Prioritized security best practices | 15+ controls |
| **PCI DSS v4.0** | Payment card data protection standard | 12+ requirements |
| **HIPAA Security Rule** | Healthcare data protection safeguards | 10+ safeguards |
| **CMMC** | Cybersecurity maturity model for defense contractors | Multi-level |

#### Initializing Frameworks

When you first set up the platform, the compliance framework database is empty. A platform administrator must seed it.

1. Navigate to the **Compliance** page from the left sidebar.
2. If no frameworks are loaded, you will see the message: "No compliance frameworks loaded."
3. Click the **Initialize Frameworks** button (visible only to `platform_admin` users).
4. The system seeds all framework definitions, control families, and individual controls into the database.
5. After seeding completes, the page reloads and displays framework cards with compliance percentages.

Alternatively, you can seed frameworks via the API:

```bash
curl -X POST https://your-instance.example.com/api/v1/compliance/seed \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

#### Viewing Framework Overview

Once frameworks are initialized, the Compliance page displays:

- **Summary cards** showing total frameworks, total controls, average compliance percentage, and count of at-risk frameworks (below 50% compliance).
- **Framework cards** for each loaded framework, displaying the framework name, version, compliance percentage, a color-coded progress bar, and total control count.

Click any framework card to expand its detail view.

### 1.2 Control Mapping and Assessment

Control mapping links vulnerability findings to specific framework controls. When a scanner detects a vulnerability, the system can automatically map it to relevant controls based on check definitions (e.g., a missing patch maps to NIST SI-2 "Flaw Remediation").

#### Viewing Controls

1. On the **Compliance** page, click a framework card to expand it.
2. The detail view shows all controls grouped by **family** (e.g., "Access Control," "System and Information Integrity").
3. Each control row displays:
   - Status icon (green check = compliant, red X = non-compliant, yellow warning = partial, gray dash = not assessed)
   - Control ID (e.g., `SI-2`, `AC-7`)
   - Control name
   - Status badge
   - Time since last assessment

#### Assessing a Control

To manually assess a control, send a POST request to the assessment endpoint. This requires the `platform_admin` or `scan_admin` role.

```bash
curl -X POST https://your-instance.example.com/api/v1/compliance/assess \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "framework_id": "fw_nist-800-53",
    "control_id": "ctrl_si-2",
    "status": "non_compliant",
    "finding_id": "find_abc123",
    "evidence": "Apache 2.4.49 unpatched on 3 production servers."
  }'
```

Valid status values are:

| Status | Meaning |
|--------|---------|
| `compliant` | All mapped findings are resolved |
| `non_compliant` | At least one open critical or high finding exists |
| `partial` | Only medium or low findings remain open |
| `not_assessed` | No scans have covered this control yet |

If a mapping already exists for the given framework and control, the system updates it in place rather than creating a duplicate.

#### Automatic Control Mapping

When scanner check definitions include compliance references, the platform automatically maps findings to controls at ingestion time. For example, a YAML check definition might include:

```yaml
compliance:
  - framework: "NIST-800-53"
    control: "SI-2"
  - framework: "PCI-DSS"
    control: "6.2"
```

When a finding is created from this check, the compliance engine links it to both SI-2 and PCI-DSS 6.2 without manual intervention.

### 1.3 Evidence Collection and Attachment

FC360 supports two types of compliance evidence: manual and auto-generated.

#### Manual Evidence

When assessing a control, include the `evidence` field in your assessment payload. This is a free-text field where you can describe the evidence supporting your assessment:

```json
{
  "framework_id": "fw_nist-800-53",
  "control_id": "ctrl_ac-7",
  "status": "compliant",
  "evidence": "Account lockout policy verified: 5 failed attempts triggers 30-minute lockout. Tested on 2025-12-01 against AD policy GPO-SEC-001."
}
```

#### Auto-Generated Evidence

The platform automatically generates evidence links from scan events. When a scan completes and findings are mapped to controls, the system creates entries in the `compliance_evidence_links` table that reference the originating event.

To view auto-generated evidence:

```bash
curl https://your-instance.example.com/api/v1/compliance/evidence/auto \
  -H "Authorization: Bearer $TOKEN"
```

You can filter by control:

```bash
curl "https://your-instance.example.com/api/v1/compliance/evidence/auto?control_id=ctrl_si-2" \
  -H "Authorization: Bearer $TOKEN"
```

When generating OSCAL SSP documents (see Section 2), auto-generated evidence is merged into controls that lack manual evidence, providing a complete evidence chain.

### 1.4 Gap Analysis and Remediation Tracking

Gap analysis identifies controls that are failing or have not been assessed, helping you prioritize remediation work.

#### Running a Gap Analysis

1. On the **Compliance** page, click a framework card to expand it.
2. Below the controls table, the **Gap Analysis** section appears automatically if gaps exist.
3. Gaps are organized into three categories:
   - **Non-Compliant** (red): Controls with at least one open critical or high finding.
   - **Partial** (yellow): Controls with open medium or low findings.
   - **Not Assessed** (gray): Controls that have not yet been evaluated by any scan.

Each gap entry shows the control ID and name. For large frameworks, the not-assessed list is truncated to 20 items with a count of remaining items.

#### API Access

```bash
curl https://your-instance.example.com/api/v1/compliance/fw_nist-800-53/gaps \
  -H "Authorization: Bearer $TOKEN"
```

The response includes the framework details and an array of gap objects grouped by status.

#### Compliance Scoring Formula

The compliance percentage for each framework is calculated as:

```
Compliance % = (Compliant Controls / Total Assessed Controls) x 100
```

Controls with `not_assessed` status are excluded from the denominator, so your percentage reflects only controls that have been evaluated.

### 1.5 POA&M Management

Plans of Action and Milestones (POA&M) track remediation commitments with deadlines. The system auto-generates POA&M entries when controls move to non-compliant status.

#### POA&M Lifecycle

```
open --> in_progress --> completed
```

Each POA&M item tracks:

- **Finding reference**: The vulnerability finding that caused the non-compliance
- **Control reference**: The framework control that is affected
- **Remediation effort**: Estimated work level (low, medium, high)
- **Scheduled completion**: Deadline based on finding severity
- **Status**: Current state of the remediation work

#### Viewing POA&M Items

POA&M data is accessible through the compliance reporting endpoints and the OSCAL POA&M export:

```bash
curl "https://your-instance.example.com/api/v1/compliance/oscal/poam" \
  -H "Authorization: Bearer $TOKEN"
```

This returns an OSCAL-formatted POA&M document containing all open and in-progress items.

#### POA&M in Reports

The vulnerabilities report (see Section 2.4) includes POA&M status for each finding, showing whether a remediation plan exists, its current status, and its due date.

### 1.6 Compliance Reporting

FC360 provides multiple reporting and export formats for compliance data.

#### OSCAL Exports

The platform generates NIST OSCAL (Open Security Controls Assessment Language) documents in both JSON and XML formats:

1. **System Security Plan (SSP)**

   ```bash
   # JSON format
   curl "https://your-instance.example.com/api/v1/compliance/fw_nist-800-53/oscal/ssp" \
     -H "Authorization: Bearer $TOKEN"

   # XML format
   curl "https://your-instance.example.com/api/v1/compliance/fw_nist-800-53/oscal/ssp?format=xml" \
     -H "Authorization: Bearer $TOKEN"
   ```

   The SSP document includes the system description, control implementations with evidence, and compliance status for every control in the selected framework.

2. **Assessment Results**

   ```bash
   curl "https://your-instance.example.com/api/v1/compliance/fw_nist-800-53/oscal/assessment" \
     -H "Authorization: Bearer $TOKEN"
   ```

   Assessment results include control findings, open vulnerabilities, and per-control pass/fail determinations.

3. **POA&M Document**

   ```bash
   curl "https://your-instance.example.com/api/v1/compliance/oscal/poam?format=xml" \
     -H "Authorization: Bearer $TOKEN"
   ```

#### Compliance Mapping Queries

To list all compliance mappings with filtering:

```bash
# All mappings for a framework
curl "https://your-instance.example.com/api/v1/compliance/mappings?framework_id=fw_nist-800-53" \
  -H "Authorization: Bearer $TOKEN"

# Non-compliant mappings only
curl "https://your-instance.example.com/api/v1/compliance/mappings?status=non_compliant" \
  -H "Authorization: Bearer $TOKEN"

# Mappings for a specific finding
curl "https://your-instance.example.com/api/v1/compliance/mappings?finding_id=find_abc123" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 2. Reporter SSP Authoring

Reporter is the report generation module. It produces security reports in PDF, CSV, and JSON formats, stores them in cloud object storage (Cloudflare R2), and provides a dashboard for generating, downloading, and managing reports. Reporter integrates tightly with FC360: the vulnerabilities report type includes compliance control mappings and POA&M tracking.

### 2.1 Generating Reports

Reporter supports five report types:

| Report Type | Description | Available Formats |
|------------|-------------|-------------------|
| **Executive Summary** | High-level security posture overview with risk score (A-F grade), severity breakdown, top risks, and recommendations | PDF, JSON |
| **Findings Report** | Detailed vulnerability listing with CVSS scores, FRS scores, affected assets, CVE data, and remediation guidance | PDF, CSV, JSON |
| **Compliance Report** | Framework compliance status across all loaded frameworks, compliance percentages, and gap analysis details | PDF, CSV, JSON |
| **Vulnerabilities (FC360)** | ForgeScan findings enriched with FC360 compliance control mappings, POA&M status, and remediation tracking | PDF, CSV, JSON |
| **Asset Inventory** | Complete asset list with hostnames, IPs, OS info, asset types, open finding counts, and risk scores | PDF, CSV, JSON |

#### Generating a Report from the Dashboard

1. Navigate to the **Reports** page from the left sidebar.
2. At the top of the page, you will see report type cards for each available report.
3. Each card shows the report name, a brief description, and format buttons (PDF, CSV, JSON).
4. Click the format button for the report you want to generate.
5. The system generates the report, stores it in R2 object storage, and triggers an automatic download in your browser.
6. The report appears in the **Generated Reports** table below the cards.

#### Generating a Report via API

```bash
curl -X POST https://your-instance.example.com/api/v1/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "findings",
    "format": "pdf",
    "title": "Q4 Vulnerability Report",
    "filters": {
      "severity": ["critical", "high"],
      "date_from": "2025-10-01",
      "date_to": "2025-12-31"
    }
  }'
```

The response includes the report ID, file size, and a download URL:

```json
{
  "id": "rpt_abc123",
  "title": "Q4 Vulnerability Report",
  "report_type": "findings",
  "format": "pdf",
  "file_size": 245780,
  "storage_key": "reports/rpt_abc123.pdf",
  "status": "completed",
  "download_url": "/api/v1/reports/rpt_abc123/download",
  "generated_at": "2025-12-15T10:30:00Z"
}
```

#### Report Filters

You can narrow report content using optional filters:

| Filter | Applies To | Description |
|--------|-----------|-------------|
| `severity` | Findings, Vulnerabilities | Array of severity levels: `["critical", "high", "medium", "low", "info"]` |
| `vendors` | Findings, Vulnerabilities | Array of scanner vendor names: `["forgescan", "nessus", "qualys"]` |
| `asset_types` | Assets | Array of asset types: `["host", "server", "workstation", "network_device"]` |
| `date_from` | Findings, Vulnerabilities | Start date (ISO 8601) |
| `date_to` | Findings, Vulnerabilities | End date (ISO 8601) |
| `framework_id` | Vulnerabilities | Filter to findings with mappings to a specific compliance framework |

#### Required Roles

Report generation requires one of the following roles: `platform_admin`, `scan_admin`, `vuln_manager`, or `auditor`.

### 2.2 Report Formats

#### PDF Reports

PDF reports are generated using the `pdf-lib` library and include:

- **Executive Summary PDF**: Risk score gauge, severity breakdown chart, top 10 risks table, and actionable recommendations.
- **Findings PDF**: Tabular listing of all findings sorted by severity and FRS score, with columns for title, severity, host, CVE, CVSS, and remediation.
- **Compliance PDF**: Per-framework compliance percentage, control family summaries, and gap details.
- **Assets PDF**: Asset inventory table with finding counts and risk indicators.

#### CSV Reports

CSV exports are available for findings, compliance, assets, and vulnerabilities reports. CSV files use UTF-8 encoding and include a header row. They are suitable for import into spreadsheet tools or SIEM systems.

For the vulnerabilities report, the `control_mappings` column is flattened to a semicolon-separated string of control IDs.

#### JSON Reports

JSON format is available for all report types and returns the raw data structure used to generate PDF and CSV versions. JSON reports are useful for programmatic consumption and integration with external systems.

The executive summary returns JSON only (not CSV), since its structure does not map cleanly to tabular format.

### 2.3 Deep Linking from Compliance Pages

The Compliance page in FC360 provides direct links to Reporter for streamlined workflows.

#### "Open in Reporter" Button

At the top of the Compliance page, the **Open in Reporter** button navigates to:

```
/reports?section=compliance
```

This opens the Reports page and scrolls to the Compliance Report card, which is highlighted with a ring border and a "Linked" badge. You can then click the format button to generate a compliance report immediately.

#### "View in Reporter" from Gap Analysis

When viewing a framework's gap analysis, the **View in Reporter** button navigates to:

```
/reports?section=vulnerabilities&framework={framework_id}
```

This opens the Reports page, scrolls to the Vulnerabilities (FC360) report card and highlights it, pre-configuring the context for a vulnerabilities report filtered by the selected framework.

#### How Deep Linking Works

Reporter reads the `section` query parameter on load and:

1. Matches it to a report type card (e.g., `section=compliance` matches the Compliance Report card).
2. Scrolls the matched card into view using smooth scrolling.
3. Highlights the card with a ring border and a "Linked" badge to draw attention.

### 2.4 Vulnerabilities Report with FC360 Control Mappings

The Vulnerabilities report type is a specialized report that bridges ForgeScan scanning results with FC360 compliance data. It is labeled "Vulnerabilities (FC360)" in the dashboard.

#### What It Contains

Each finding in the vulnerabilities report includes:

- **Finding details**: Title, description, severity, state, CVE ID, CVSS v3 score, FRS score
- **Affected component**: Software or service that is vulnerable
- **Solution**: Recommended remediation action
- **Asset context**: Hostname, IP addresses, asset type, OS, network zone
- **Control mappings**: Array of FC360 compliance controls that this finding maps to (parsed from the `control_mappings` JSON field)
- **POA&M status**: Whether a POA&M item exists, its current status (`open`, `in_progress`, `completed`), remediation effort estimate, and due date

#### Report Summary

The summary section includes:

| Metric | Description |
|--------|-------------|
| Total open findings | Count of all findings in `open` state |
| Severity breakdown | Critical, high, medium, low, and info counts |
| Mapped to controls | Number of findings that have FC360 control mappings |
| Affected assets | Count of unique assets with open findings |
| Total POA&M items | Count of all POA&M entries |
| Open POA&M | POA&M items still in `open` status |
| Overdue POA&M | POA&M items past their scheduled completion date |

#### Filtering by Framework

To generate a vulnerabilities report limited to findings that map to a specific framework:

```bash
curl -X POST https://your-instance.example.com/api/v1/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "vulnerabilities",
    "format": "pdf",
    "filters": {
      "framework_id": "fw_nist-800-53"
    }
  }'
```

When `framework_id` is specified, only findings with non-empty `control_mappings` are included.

#### CSV Export with Control Mappings

In CSV format, the control mappings column contains semicolon-separated control IDs:

```csv
title,severity,cve_id,cvss3_score,control_mappings,poam_status
"Apache Path Traversal",high,CVE-2021-41773,7.5,"SI-2; 6.2",open
```

### 2.5 Downloading and Managing Generated Reports

#### Viewing Generated Reports

The **Generated Reports** table on the Reports page shows all previously generated reports with:

- Title
- Report type (badge)
- Format (PDF/CSV/JSON with icon)
- File size (human-readable)
- Status (Completed/Failed/Pending)
- Generation timestamp
- Action buttons

#### Downloading a Report

**From the Dashboard:**
Click the download icon button in the Actions column of any completed report.

**Via API:**
```bash
curl -o report.pdf \
  https://your-instance.example.com/api/v1/reports/{report_id}/download \
  -H "Authorization: Bearer $TOKEN"
```

The download endpoint returns the file with appropriate `Content-Type` and `Content-Disposition` headers:
- PDF: `application/pdf`
- CSV: `text/csv; charset=utf-8`
- JSON: `application/json`

#### Listing All Reports

```bash
curl "https://your-instance.example.com/api/v1/reports/list/all?limit=20&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```

You can filter by report type:

```bash
curl "https://your-instance.example.com/api/v1/reports/list/all?report_type=executive" \
  -H "Authorization: Bearer $TOKEN"
```

#### Deleting a Report

Only `platform_admin` users can delete reports. Deletion removes both the metadata record from the database and the file from R2 object storage.

**From the Dashboard:**
Click the trash icon button in the Actions column.

**Via API:**
```bash
curl -X DELETE https://your-instance.example.com/api/v1/reports/{report_id} \
  -H "Authorization: Bearer $TOKEN"
```

---

## 3. ForgeScan Scanning

ForgeScan is the vulnerability scanning engine. It uses a distributed architecture: the cloud API orchestrates scans, and Rust-based scanner agents deployed on-premises or in the cloud execute the actual scanning work. Scanners poll the API for tasks, run scans against target networks, and submit results back to the API for storage and analysis.

### 3.1 Scanner Registration and Management

Before a scanner can receive and execute scan tasks, it must be registered with the platform.

#### Registering a Scanner from the Dashboard

1. Navigate to the **Scanners** page from the left sidebar (requires `platform_admin` role).
2. Click **Register Scanner**.
3. Fill in the required fields:
   - **Scanner ID**: A unique identifier for this scanner (e.g., `scanner-hq-internal`)
   - **Hostname**: The machine hostname where the scanner runs
   - **Version**: Scanner software version (optional)
   - **Capabilities**: Array of scan types this scanner supports (e.g., `["network", "vulnerability", "webapp", "discovery"]`)
4. Click **Register**.
5. The system generates and displays a `SCANNER_API_KEY`. **Copy this key immediately** -- it will not be shown again.

#### Registering via API

```bash
curl -X POST https://your-instance.example.com/api/v1/scanner/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "scanner_id": "scanner-hq-internal",
    "hostname": "scan01.internal.example.com",
    "version": "0.1.0",
    "capabilities": ["network", "vulnerability", "webapp", "discovery", "cloud"]
  }'
```

Response:

```json
{
  "id": "uuid-of-registration",
  "scanner_id": "scanner-hq-internal",
  "hostname": "scan01.internal.example.com",
  "api_key": "scanner_a1b2c3d4e5f6...",
  "api_key_prefix": "scanner_",
  "message": "Store this API key securely - it will not be shown again"
}
```

#### Configuring the Scanner Binary

Store the API key and scanner ID in the scanner configuration file at `/etc/forgescan/scanner.toml` or as environment variables:

```toml
# /etc/forgescan/scanner.toml
[platform]
url = "https://your-instance.example.com"
scanner_id = "scanner-hq-internal"
api_key = "scanner_a1b2c3d4e5f6..."

[scanner]
poll_interval_secs = 10
heartbeat_interval_secs = 120
```

Or via environment variables:

```bash
export FORGESCAN_PLATFORM_URL="https://your-instance.example.com"
export FORGESCAN_SCANNER_ID="scanner-hq-internal"
export FORGESCAN_API_KEY="scanner_a1b2c3d4e5f6..."
```

#### Viewing Registered Scanners

The Scanners page (or `GET /api/v1/scanner/`) displays all registered scanners with:

- Scanner ID and hostname
- Current status (`registered`, `active`, `disabled`)
- Last heartbeat timestamp
- Task counts: completed, running, and assigned
- Software version and capabilities

#### Deactivating a Scanner

To disable a scanner without deleting its records:

```bash
curl -X DELETE https://your-instance.example.com/api/v1/scanner/{registration_id} \
  -H "Authorization: Bearer $TOKEN"
```

This sets the scanner status to `disabled`. Disabled scanners are rejected when they attempt to authenticate.

### 3.2 Agent Registration

The ForgeScan Agent (`forgescan-agent`) is a lightweight endpoint binary that runs directly on hosts. Unlike the network scanner, the agent performs local operations: configuration auditing, patch detection, and file integrity monitoring.

#### Installing the Agent

**Linux:**
```bash
./deploy/onprem/install.sh \
  --api-key "scanner_a1b2c3d4..." \
  --scanner-id "agent-web01"
```

**Windows:**
```powershell
.\install-windows.ps1 -ApiKey "scanner_a1b2c3d4..." -ScannerId "agent-web01"
```

**With Xiid SealedTunnel (zero inbound ports):**
```bash
./deploy/onprem/install.sh \
  --api-key "scanner_a1b2c3d4..." \
  --scanner-id "agent-web01" \
  --use-sealedtunnel \
  --stlink-config /path/to/stlink.json
```

#### Agent Communication

The agent communicates with the platform API using REST transport over HTTPS. It authenticates using the `X-Scanner-Key` header, the same mechanism as network scanners. The communication loop is:

1. **Heartbeat**: Every 120 seconds, the agent sends `POST /api/v1/scanner/heartbeat` with its hostname, version, and capabilities.
2. **Task polling**: Every 10 seconds, the agent calls `GET /api/v1/scanner/tasks/next` to check for assigned work.
3. **Result submission**: After completing a task, the agent sends `POST /api/v1/scanner/tasks/{id}/results` with findings and asset data.

All communication is outbound-only on port 443. No inbound ports are required on the agent host.

#### Agent CLI Options

```
forgescan-agent [OPTIONS]

Options:
  -c, --config <PATH>         Configuration file path
      --log-level <LEVEL>     Log level: trace, debug, info, warn, error [default: info]
      --platform <URL>        Platform API endpoint
      --register              Run registration and exit
      --scan-now              Run a single scan and exit (for testing)
      --format <FORMAT>       Output format: json, text, table [default: text]
      --failures-only         Only show failed checks
      --min-severity <LEVEL>  Filter by minimum severity: low, medium, high, critical
      --system-info           Collect and display system information
```

### 3.3 Scan Types

ForgeScan supports the following scan types. When creating a scan, specify the type in the `scan_type` field.

| Scan Type | Value | Description | Scanner Crate |
|-----------|-------|-------------|---------------|
| Network Discovery | `network` | ARP/ICMP/TCP SYN probes to find live hosts, port scanning, service detection, OS fingerprinting | `forgescan-network` |
| Vulnerability Scan | `vulnerability` | CPE-based version matching against local NVD database, CVE detection, FRS calculation | `forgescan-vuln` + `forgescan-nvd` |
| Web Application | `webapp` | OWASP Top 10 testing: SQL injection, XSS, CSRF, broken authentication, security misconfigurations | `forgescan-webapp` |
| Discovery | `discovery` | Lightweight host discovery only (no vulnerability assessment) | `forgescan-network` |
| Full Scan | `full` | Combined network discovery, port scan, service detection, and vulnerability assessment | Multiple crates |
| Cloud Scan | `cloud` | AWS/Azure/GCP misconfiguration checks: IAM policies, S3 buckets, security groups | `forgescan-cloud` |
| Config Audit | `config_audit` | CIS Benchmark and DISA STIG compliance checks on endpoints | `forgescan-config-audit` |
| Container Scan | `container` | Docker/OCI image vulnerability analysis | Via API routes |
| Code Scan | `code` | SAST static analysis for code-level vulnerabilities | Via API routes |
| Packet Capture | `capture` | Network traffic capture to PCAP format, uploaded to R2 storage (max 100 MB) | Scanner binary |

### 3.4 Configuration Auditing

Configuration auditing checks endpoint configurations against CIS Benchmark and DISA STIG standards. This runs via the `forgescan-agent` binary on each endpoint.

#### Supported Checks

The `forgescan-config-audit` crate includes checks for:

**Linux Systems:**
- File permissions (e.g., `/etc/passwd`, `/etc/shadow`, SSH config files)
- Service configuration (running services, enabled services, startup settings)
- Kernel parameters and sysctl settings
- User account policies (password aging, unused accounts)
- Network configuration (IP forwarding, ICMP redirects)

**Windows Systems:**
- Registry values (security policies, audit settings, service configurations)
- Service states (running, stopped, disabled)
- User account checks (password policies, account lockout)
- Windows firewall configuration

#### Running a Configuration Audit

**Interactive single scan:**
```bash
forgescan-agent --scan-now --format table
```

**Show only failures:**
```bash
forgescan-agent --scan-now --failures-only --format text
```

**Filter by minimum severity:**
```bash
forgescan-agent --scan-now --min-severity high --format json
```

**Collect system information:**
```bash
forgescan-agent --system-info
```

This displays hardware info, OS details, installed packages, running services, network interfaces, and user accounts.

#### Audit Results

Each check produces a result containing:

- **Check name**: Human-readable description (e.g., "Ensure SSH root login is disabled")
- **Check type**: Category of the check (file permission, service state, registry value, etc.)
- **Status**: `passed` or `failed`
- **Expected value**: What the check requires
- **Actual value**: What was found on the system
- **Severity**: Critical, high, medium, or low
- **Compliance mapping**: References to CIS/STIG control IDs

The audit summary includes total checks run, pass/fail counts, and compliance coverage percentages.

### 3.5 Running Scans and Viewing Results

#### Creating a Scan from the Dashboard

1. Navigate to the **Scans** page from the left sidebar.
2. Click **New Scan**.
3. Fill in the scan configuration:
   - **Name**: A descriptive name for this scan (e.g., "Weekly Internal Network Scan")
   - **Type**: Select from the dropdown (network, vulnerability, webapp, full, etc.)
   - **Target**: IP address, CIDR range, hostname, or domain (e.g., `192.168.1.0/24`, `example.com`)
   - **Configuration**: Optional JSON configuration for advanced settings
4. Click **Create** to save the scan in `pending` status.

#### Starting a Scan

After creating a scan, you must start it to begin execution:

1. On the Scans page, find your pending scan.
2. Click the **Start** button.
3. The scan orchestrator creates scanner tasks based on the scan type and targets.
4. Tasks are queued for pickup by registered scanner agents.

Via API:

```bash
# Create scan
curl -X POST https://your-instance.example.com/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "DMZ Vulnerability Scan",
    "type": "vulnerability",
    "target": "10.0.1.0/24"
  }'

# Start scan (using the returned scan ID)
curl -X POST https://your-instance.example.com/api/v1/scans/{scan_id}/start \
  -H "Authorization: Bearer $TOKEN"
```

#### Monitoring Scan Progress

The dashboard polls for active scan status automatically. For each running scan, you can see:

- **Progress bar**: Percentage of tasks completed
- **Task breakdown**: Queued, assigned, running, completed, and failed task counts
- **Findings count**: Vulnerabilities discovered so far
- **Assets count**: Hosts discovered

Via API, check active scans:

```bash
curl https://your-instance.example.com/api/v1/scans/active \
  -H "Authorization: Bearer $TOKEN"
```

Or view tasks for a specific scan:

```bash
curl https://your-instance.example.com/api/v1/scans/{scan_id}/tasks \
  -H "Authorization: Bearer $TOKEN"
```

#### Scan Lifecycle

```
pending --> running --> completed
                   \--> failed
pending --> cancelled
running --> cancelled
```

To cancel a running scan:

```bash
curl -X POST https://your-instance.example.com/api/v1/scans/{scan_id}/cancel \
  -H "Authorization: Bearer $TOKEN"
```

Cancellation stops all queued and assigned tasks associated with the scan.

### 3.6 Asset Discovery and Inventory

ForgeScan automatically builds and maintains an asset inventory from scan results.

#### How Assets Are Discovered

When a scanner completes a task, it submits discovered assets along with findings. The API processes assets as follows:

1. For each asset in the results, the system checks if an asset with the same IP address or hostname already exists.
2. If the asset exists, its record is updated with new OS and type information, and the `last_seen` timestamp is refreshed.
3. If the asset is new, a record is created in the `assets` table with hostname, IP, OS, asset type, and organization ID.

#### Viewing the Asset Inventory

Navigate to the **Assets** page to see all discovered assets. Each asset row shows:

- Hostname and IP addresses
- Operating system
- Asset type (host, server, workstation, network device, etc.)
- Open findings count
- Critical and high finding counts
- Maximum FRS score across all findings

#### Asset Reports

Generate an asset inventory report from Reporter:

```bash
curl -X POST https://your-instance.example.com/api/v1/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "assets",
    "format": "csv",
    "filters": {
      "asset_types": ["server", "workstation"]
    }
  }'
```

The asset report includes a summary (total assets, asset type count, network zone count) and a breakdown by asset type.

### 3.7 Finding Management and Remediation

Findings are the core data object in ForgeScan. Each finding represents a vulnerability or misconfiguration discovered during a scan.

#### Finding Attributes

| Field | Description |
|-------|-------------|
| `title` | Descriptive name of the vulnerability |
| `description` | Detailed explanation |
| `severity` | critical, high, medium, low, or info |
| `state` | open, fixed, accepted, or false_positive |
| `cve_id` | Associated CVE identifier |
| `cvss3_score` | CVSS v3 base score |
| `frs_score` | Forge Risk Score (0-100, factors in exploit maturity, threat intel, asset criticality) |
| `port` | Affected port number |
| `protocol` | TCP or UDP |
| `service` | Detected service name |
| `solution` | Recommended remediation action |
| `evidence` | Technical proof of the vulnerability |
| `vendor` | Scanner vendor that discovered it (forgescan, nessus, qualys, etc.) |
| `control_mappings` | JSON array of FC360 compliance control references |
| `first_seen` | When the finding was first discovered |
| `last_seen` | When the finding was last confirmed |

#### Viewing Findings

Navigate to the **Findings** page to see all vulnerability findings. The list is sorted by severity and FRS score by default. You can filter by:

- Severity level
- Finding state
- Vendor/scanner source
- Asset type
- Date range

#### Finding Lifecycle

```
open --> fixed          (vulnerability patched, confirmed by rescan)
open --> accepted       (risk accepted, no remediation planned)
open --> false_positive (determined not to be a real vulnerability)
```

When a finding moves to `fixed` state, the compliance engine recalculates control status. If all findings mapped to a control are resolved, the control moves to `compliant` status.

#### Forge Risk Score (FRS)

Every finding receives an FRS that goes beyond raw CVSS to incorporate real-world threat context:

```
FRS = CVSS Base Score
    x Exploit Maturity     (1.0 = unproven, 1.5 = functional, 2.0 = high)
    x Threat Intelligence  (1.0 = no active exploits, 2.0 = widespread in-the-wild)
    x Asset Criticality    (1.0 = low-value asset, 2.0 = crown jewels)
    x Exposure Factor      (1.0 = internal only, 2.0 = internet-facing)
    x Age Factor           (1.0 = old finding, 1.5 = discovered this week)

Final score: 0-100 (normalized)
```

FRS drives prioritization across the platform: dashboard risk grades, SLA deadlines, alert severity, and compliance gap urgency all reference FRS.

#### Event-Driven Automation

When a high or critical finding is created, the event bus publishes a `forge.vulnerability.detected` event. This can trigger:

- **ForgeSOC alerts**: Detection rules match the event and create SOC alerts with MITRE ATT&CK mappings.
- **SOAR playbooks**: Automated response actions such as Slack notifications, Jira ticket creation, or host isolation.
- **Threat intel correlation**: The finding's CVE is checked against the CISA KEV catalog and other threat feeds.
- **Compliance mapping**: The finding is automatically mapped to relevant framework controls.

#### Importing Third-Party Findings

ForgeScan can ingest vulnerability data from external scanners. Navigate to the **Import** page and upload files in these formats:

- **Nessus** (.nessus XML)
- **Qualys** (CSV or XML)
- **Rapid7** (CSV or XML)
- **SARIF** (Static Analysis Results Interchange Format)
- **CycloneDX** (SBOM format)
- **Generic CSV** (with mapped column headers)

Imported findings are normalized to the ForgeScan data model and integrated with the same compliance mapping, risk scoring, and reporting workflows as natively discovered findings.

---

## Appendix: Role Permissions

| Role | Scans | Findings | Reports | Compliance | Scanners | Users |
|------|-------|----------|---------|------------|----------|-------|
| `platform_admin` | Full | Full | Full | Full (including seed/assess) | Full | Full |
| `scan_admin` | Full | Full | Generate/Download | Assess | View | -- |
| `vuln_manager` | Create/Start | View/Manage | Generate/Download | View | -- | -- |
| `remediation_owner` | -- | View assigned/Update status | -- | View | -- | -- |
| `auditor` | View | View | Generate/Download | View | View | -- |

## Appendix: API Quick Reference

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List frameworks | GET | `/api/v1/compliance` |
| Framework details | GET | `/api/v1/compliance/:id` |
| Framework controls | GET | `/api/v1/compliance/:id/controls` |
| Gap analysis | GET | `/api/v1/compliance/:id/gaps` |
| Seed frameworks | POST | `/api/v1/compliance/seed` |
| Assess control | POST | `/api/v1/compliance/assess` |
| OSCAL SSP | GET | `/api/v1/compliance/:id/oscal/ssp` |
| OSCAL Assessment | GET | `/api/v1/compliance/:id/oscal/assessment` |
| OSCAL POA&M | GET | `/api/v1/compliance/oscal/poam` |
| Auto evidence | GET | `/api/v1/compliance/evidence/auto` |
| Generate report | POST | `/api/v1/reports/generate` |
| Download report | GET | `/api/v1/reports/:id/download` |
| List reports | GET | `/api/v1/reports/list/all` |
| Delete report | DELETE | `/api/v1/reports/:id` |
| Register scanner | POST | `/api/v1/scanner/register` |
| List scanners | GET | `/api/v1/scanner/` |
| Deactivate scanner | DELETE | `/api/v1/scanner/:id` |
| Scanner heartbeat | POST | `/api/v1/scanner/heartbeat` |
| Poll for tasks | GET | `/api/v1/scanner/tasks/next` |
| Submit results | POST | `/api/v1/scanner/tasks/:id/results` |
| Create scan | POST | `/api/v1/scans` |
| Start scan | POST | `/api/v1/scans/:id/start` |
| Cancel scan | POST | `/api/v1/scans/:id/cancel` |
| Active scans | GET | `/api/v1/scans/active` |
| Scan tasks | GET | `/api/v1/scans/:id/tasks` |
| Scan stats | GET | `/api/v1/scans/stats/summary` |
