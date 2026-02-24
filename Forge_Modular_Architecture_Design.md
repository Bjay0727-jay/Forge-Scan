# Forge Platform -- Modular Architecture Design

## 1. Executive Summary

The Forge ecosystem consists of three products that share significant overlapping infrastructure, data models, and integration patterns:

| Product | Purpose |
|---------|---------|
| **ForgeScan** | Continuous vulnerability scanning, asset discovery, risk scoring (FRS) |
| **ForgeSOC** | 24/7 threat monitoring, detection, incident response, compliance-aware SIEM |
| **ForgeRedOps** | Offensive security -- AI pen testing (24 agents), exploit validation, automated remediation |

All three products share: a compliance integration layer (ForgeComply 360), overlapping data models (assets, vulnerabilities, findings), similar tech stacks (Cloudflare Workers, PostgreSQL/D1, Redis, Kafka), and common UI patterns (dark theme, Plus Jakarta Sans, emerald branding).

**This document proposes a monorepo-based modular architecture** where shared capabilities live in a core platform layer, and each product extends it with domain-specific modules.

---

## 2. Current State Analysis

### 2.1 Shared Components Across Products

| Capability | ForgeScan | ForgeSOC | ForgeRedOps |
|------------|:---:|:---:|:---:|
| Asset Inventory | Yes | Yes (via sync) | Yes (847+ assets) |
| Vulnerability Data | Yes (primary) | Yes (consumes) | Yes (extends with pen test) |
| NIST 800-53 Mapping | Yes | Yes (detection rules) | Yes (94% auto-mapping) |
| ForgeComply 360 Sync | Yes | Yes (bi-directional) | Yes (auto-POA&M) |
| Risk Scoring | FRS (0-100) | Alert Severity | CVSS + Criticality + Exploitability |
| MITRE ATT&CK | Partial | 847 rules mapped | Pen test agent coverage |
| API Gateway | Yes | Yes | Yes |
| Notification System | Yes (Slack, Teams, PD) | Yes (same set) | Yes (same set) |
| Ticketing Integration | Jira, ServiceNow, ADO | Jira, ServiceNow, Zendesk | Jira, ServiceNow |
| SIEM Integration | Splunk, QRadar, Sentinel | Native + external | Via ForgeScan |
| Authentication/RBAC | SecOps Admin, Vuln Mgr, Remediation Owner | SOC Analyst, SOC Manager, IR Lead | Pen Tester, Red Team Lead |
| Kubernetes Deployment | EKS | EKS | EKS |

### 2.2 Key Insight

~60-70% of the infrastructure is duplicated across products. A unified platform core would eliminate redundancy, reduce maintenance burden, and enable cross-product workflows (e.g., a vulnerability found by ForgeScan triggers a ForgeRedOps pen test, which generates a ForgeSOC alert if exploitation succeeds).

---

## 3. Recommended Modular Architecture

### 3.1 Architecture Layers

```
+================================================================+
|                      FORGE PLATFORM CORE                        |
|  (Shared across all products)                                   |
|                                                                  |
|  +------------------+  +------------------+  +----------------+ |
|  | Asset Registry   |  | Identity & RBAC  |  | Event Bus      | |
|  | (unified asset   |  | (SSO, roles,     |  | (Kafka/Redis   | |
|  |  inventory)      |  |  tenancy)        |  |  Streams)      | |
|  +------------------+  +------------------+  +----------------+ |
|                                                                  |
|  +------------------+  +------------------+  +----------------+ |
|  | Compliance Core  |  | Integration Hub  |  | Notification   | |
|  | (NIST, CIS, PCI, |  | (ticketing,SIEM, |  | Engine         | |
|  |  HIPAA mappings)  |  |  webhooks, APIs) |  | (Slack,Teams,  | |
|  +------------------+  +------------------+  |  PD, Email)    | |
|                                               +----------------+ |
|  +------------------+  +------------------+  +----------------+ |
|  | Data Layer       |  | API Gateway      |  | UI Shell       | |
|  | (PostgreSQL, D1, |  | (auth, rate      |  | (shared layout,| |
|  |  Redis, R2)      |  |  limit, routing) |  |  design system)| |
|  +------------------+  +------------------+  +----------------+ |
+================================================================+
         |                      |                      |
+================+  +==================+  +==================+
| FORGESCAN  |  |    FORGE SOC     |  |  FORGE REDOPS    |
| MODULE         |  |    MODULE        |  |  MODULE          |
|                |  |                  |  |                  |
| - Scan Orch.   |  | - Detection Eng. |  | - AI Pen Test    |
| - Ingestion    |  | - ForgeML Corr.  |  |   (24 agents)    |
| - FRS Engine   |  | - Incident Resp. |  | - Exploit Valid.  |
| - Discovery    |  | - Playbooks      |  | - Attack Sim.     |
| - ASM Engine   |  | - SOC Workbench  |  | - Recon Engine    |
| - Cert Monitor |  | - Threat Intel   |  | - Report Gen.     |
+================+  +==================+  +==================+
         |                      |                      |
+================================================================+
|                   FORGE COMPLY 360                               |
|  (Compliance & Governance -- separate product, shared API)      |
|  Risk Register | Evidence Vault | POA&M | Audit Trail           |
+================================================================+
```

### 3.2 Shared Core Modules (Build First)

#### Module 1: Asset Registry (`@forge/asset-registry`)
Single source of truth for all assets across the platform.

**Responsibilities:**
- Unified asset model (hostname, IP, OS, location, criticality, owner, tags)
- Asset classification (Managed / Unmanaged / Rogue)
- Asset-to-vulnerability relationship tracking
- Asset criticality scoring
- Multi-source deduplication (network scan, cloud APIs, CMDB, AD)

**Why shared:** All three products need asset data. ForgeScan discovers them, ForgeSOC monitors them, ForgeRedOps tests them. One registry prevents data drift.

**Data Model:**
```
Asset {
  id: UUID
  hostname: string
  ip_addresses: string[]
  mac_address: string?
  os: string
  os_version: string
  classification: "managed" | "unmanaged" | "rogue"
  criticality: "low" | "medium" | "high" | "critical"
  owner_id: UUID
  site_id: UUID
  tags: string[]
  sources: AssetSource[]  // which systems reported this asset
  first_seen: timestamp
  last_seen: timestamp
  cloud_metadata: JSON?   // AWS/Azure/GCP specific
}
```

#### Module 2: Compliance Core (`@forge/compliance-core`)
Shared compliance mapping and control framework.

**Responsibilities:**
- NIST 800-53, CIS Benchmark, PCI-DSS, HIPAA, DISA STIG control definitions
- Finding-to-control mapping logic (used by all three products)
- Auto-POA&M generation (shared between ForgeScan and ForgeRedOps)
- Control health scoring
- Evidence attachment and linking
- Bi-directional ForgeComply 360 sync API client

**Why shared:** ForgeScan maps vulnerabilities to controls. ForgeSOC maps detections to controls. ForgeRedOps maps pen test findings to controls. The mapping logic is identical.

#### Module 3: Integration Hub (`@forge/integration-hub`)
Unified connector framework for external systems.

**Responsibilities:**
- Ticketing connectors (Jira, ServiceNow, Azure DevOps, Zendesk)
- SIEM connectors (Splunk, QRadar, Azure Sentinel)
- Notification dispatch (Email, Slack, MS Teams, PagerDuty)
- Webhook dispatcher (outbound events)
- Connector health monitoring
- Rate limiting and retry logic

**Plugin architecture:**
```
IntegrationConnector {
  id: string
  type: "ticketing" | "siem" | "notification" | "cloud" | "custom"
  config: ConnectorConfig

  send(event: ForgeEvent): Promise<void>
  receive(): AsyncIterator<ExternalEvent>
  healthCheck(): Promise<HealthStatus>
}
```

**Why shared:** All three products integrate with the same external tools. Building connectors once and sharing them eliminates the #1 source of integration maintenance overhead.

#### Module 4: Event Bus (`@forge/event-bus`)
Central event backbone enabling cross-product workflows.

**Responsibilities:**
- Publish/subscribe for internal events
- Event schema registry (versioned event types)
- Cross-product event routing
- Event persistence for audit trail
- Dead letter queue for failed handlers

**Key Event Types:**
```
forge.asset.discovered
forge.asset.classification_changed
forge.vulnerability.detected
forge.vulnerability.status_changed
forge.scan.completed
forge.pentest.finding
forge.pentest.exploitation_success
forge.soc.alert_created
forge.soc.incident_created
forge.compliance.control_failed
forge.compliance.poam_generated
```

**Why shared:** This is the glue that enables the killer cross-product workflows described in Section 4.

#### Module 5: API Gateway (`@forge/gateway`)
Unified API entry point.

**Responsibilities:**
- Authentication (SSO, API keys, OAuth 2.0)
- Authorization (RBAC per product module)
- Rate limiting
- Request routing to product-specific APIs
- API versioning
- OpenAPI schema generation

**Route Structure:**
```
/api/v1/assets/*          -> @forge/asset-registry
/api/v1/compliance/*      -> @forge/compliance-core
/api/v1/integrations/*    -> @forge/integration-hub
/api/v1/scan/*            -> @forge/forgescan module
/api/v1/soc/*             -> @forge/forgesoc module
/api/v1/redops/*          -> @forge/forgeredops module
```

#### Module 6: UI Shell (`@forge/ui-shell`)
Shared frontend application shell.

**Responsibilities:**
- Design system (Forge Emerald theme, component library)
- Application layout (header, sidebar, main content, right panel)
- Navigation framework (product switching)
- Shared dashboard widgets (asset counts, risk scores, compliance gauges)
- Authentication UI
- Notification center

**Why shared:** The existing HTML mockups show identical design patterns. A shared design system ensures consistency and cuts frontend effort significantly.

---

### 3.3 Product-Specific Modules

#### ForgeScan Module (`@forge/forgescan`)
| Sub-Module | Responsibility |
|---|---|
| Scan Orchestrator | Job scheduling, Nessus/Tenable API integration, scan policies |
| Ingestion Pipeline | Download, parse, normalize scan results |
| FRS Engine | ForgeScan Risk Score calculation (CVSS + exploit maturity + threat intel + asset criticality + exposure + age) |
| Discovery Engine | Multi-source asset collection, fingerprinting, deduplication, rogue detection |
| ASM Engine | External attack surface monitoring, subdomain enumeration, SSL cert tracking, Shadow IT detection |

#### ForgeSOC Module (`@forge/forgesoc`)
| Sub-Module | Responsibility |
|---|---|
| Data Ingestion | 100+ source collectors, CEF normalization |
| Detection Engine | 847 MITRE ATT&CK rules, signature + behavioral + ForgeML correlation |
| Incident Management | Case creation, timeline, evidence chain, escalation |
| Playbook Engine | 50+ automated response playbooks (NIST 800-61 aligned) |
| SOC Workbench | Analyst UI, investigation tools, threat hunting queries |
| Threat Intelligence | External feed ingestion, IOC management, TI enrichment |

#### ForgeRedOps Module (`@forge/forgeredops`)
| Sub-Module | Responsibility |
|---|---|
| AI Pen Test Controller | Orchestration of 24 autonomous agents |
| Agent Framework | Agent lifecycle, task assignment, safe exploitation guardrails |
| Web App Agents (6) | OWASP Top 10, injection, XSS, CSRF, SSRF testing |
| API Security Agents (4) | Auth bypass, BOLA, rate limit testing |
| Cloud Config Agents (6) | IAM misconfig, privilege escalation testing |
| Network Agents (4) | Port scanning, service enumeration, lateral movement |
| Identity Agents (4) | Credential testing, session hijacking |
| Recon Engine | Attack surface discovery, target profiling |
| Report Generator | Findings report with remediation guidance |

---

## 4. Cross-Product Workflows (Key Value of Modularity)

These workflows are only possible with the shared event bus and unified data model.

### Workflow 1: Vulnerability-to-Exploitation Validation
```
ForgeScan detects CVE-2025-1234 on web-prod-01
  -> Event: forge.vulnerability.detected (FRS: 98.5, Critical)
  -> ForgeRedOps auto-triggers targeted pen test on that CVE
     -> AI agent attempts safe exploitation
     -> Result: Exploitation successful
        -> Event: forge.pentest.exploitation_success
        -> ForgeSOC creates high-priority alert
        -> Auto-POA&M generated in ForgeComply 360
        -> PagerDuty notification sent to asset owner
```

### Workflow 2: Threat Detection to Vulnerability Correlation
```
ForgeSOC detects lateral movement from 10.10.50.142
  -> Event: forge.soc.alert_created (MITRE: T1021)
  -> Asset Registry lookup: 10.10.50.142 = "unknown-device-01" (Rogue)
  -> ForgeScan triggers emergency scan on that IP
  -> ForgeRedOps runs network agent against the host
  -> Correlated finding: Rogue device with 12 critical vulnerabilities
     actively being used for lateral movement
```

### Workflow 3: Compliance Continuous Monitoring
```
ForgeScan weekly scan finds 45 hosts missing patches
  -> Compliance Core maps to SI-2 (Flaw Remediation)
  -> Control health drops below threshold
  -> ForgeSOC monitoring detects compliance drift
  -> Auto-POA&M entries created with AI-generated milestones
  -> Jira tickets created for remediation owners
  -> 30-day SLA clock starts
```

---

## 5. Technology Stack Recommendations

### 5.1 Monorepo Structure

```
forge-platform/
├── packages/
│   ├── core/
│   │   ├── asset-registry/       # @forge/asset-registry
│   │   ├── compliance-core/      # @forge/compliance-core
│   │   ├── integration-hub/      # @forge/integration-hub
│   │   ├── event-bus/            # @forge/event-bus
│   │   ├── gateway/              # @forge/gateway
│   │   └── ui-shell/             # @forge/ui-shell
│   ├── products/
│   │   ├── forgescan/            # @forge/forgescan
│   │   ├── forgesoc/             # @forge/forgesoc
│   │   └── forgeredops/          # @forge/forgeredops
│   └── shared/
│       ├── types/                # @forge/types (shared TypeScript types)
│       ├── utils/                # @forge/utils (common helpers)
│       └── test-utils/           # @forge/test-utils
├── infrastructure/
│   ├── terraform/                # IaC for AWS EKS, RDS, ElastiCache
│   ├── k8s/                      # Kubernetes manifests / Helm charts
│   └── cloudflare/               # Workers, D1, R2 configs
├── docs/
│   ├── architecture/
│   ├── api/
│   └── runbooks/
├── turbo.json                    # Turborepo config
├── package.json
└── tsconfig.base.json
```

### 5.2 Recommended Tech Stack

| Layer | Technology | Rationale |
|---|---|---|
| **Language** | TypeScript (full stack) | Shared types between API and UI, strong ecosystem |
| **Backend Runtime** | Node.js + Cloudflare Workers | Matches existing design docs; Workers for edge, Node for heavy compute |
| **API Framework** | Hono | Runs on both Node.js and Cloudflare Workers |
| **Database** | PostgreSQL (primary), Cloudflare D1 (edge) | Already in architecture; D1 for edge-cached reads |
| **Cache** | Redis Cluster | Already in architecture; session, rate limiting, pub/sub |
| **Message Queue** | Apache Kafka | Already in ForgeSOC design; handles high-volume event streaming |
| **Object Storage** | Cloudflare R2 / AWS S3 | Scan results, reports, evidence files |
| **Search** | Elasticsearch | Already in ForgeSOC for log search; extend for vuln search |
| **AI/ML** | Claude API (cloud), Ollama + Llama 3 (air-gapped) | Already in both ForgeSOC and ForgeRedOps designs |
| **Frontend** | React + Next.js | Component-based, SSR for dashboards, strong ecosystem |
| **UI Components** | Tailwind CSS + Radix UI | Matches existing dark theme; accessible primitives |
| **Charts** | Chart.js (existing) or Recharts | Already used in mockups |
| **Monorepo Tool** | Turborepo | Fast builds, task caching, dependency graph awareness |
| **Container** | Docker + Kubernetes (EKS) | Already in architecture |
| **IaC** | Terraform | Standard for AWS + Cloudflare provisioning |
| **CI/CD** | GitHub Actions | Monorepo-aware, Turborepo integration |

### 5.3 Deployment Architecture

```
                    Cloudflare Edge
                    ┌─────────────────────┐
                    │ Workers (API Gateway)│
                    │ D1 (edge cache)      │
                    │ R2 (object storage)  │
                    └─────────┬───────────┘
                              │
                    AWS EKS Cluster
         ┌────────────────────┼────────────────────┐
         │                    │                     │
   ┌─────┴─────┐      ┌──────┴──────┐      ┌──────┴──────┐
   │ ForgeScan  │      │  ForgeSOC   │      │ ForgeRedOps │
   │ Pods       │      │  Pods       │      │ Pods        │
   │ (scan orch,│      │ (detection, │      │ (AI agents, │
   │  ingestion,│      │  incident,  │      │  recon,     │
   │  FRS)      │      │  playbooks) │      │  exploit)   │
   └─────┬─────┘      └──────┬──────┘      └──────┬──────┘
         │                    │                     │
   ┌─────┴────────────────────┴─────────────────────┴─────┐
   │                   Shared Services                      │
   │  PostgreSQL (HA)  │  Redis Cluster  │  Kafka  │  ES   │
   └───────────────────────────────────────────────────────┘
```

---

## 6. Data Architecture

### 6.1 Shared Database Schema Strategy

Use a **schema-per-module** approach within a single PostgreSQL cluster:

```
forge_core          -- Asset Registry, RBAC, Audit
forge_compliance    -- Controls, mappings, POA&Ms
forge_integrations  -- Connector configs, webhook logs
forge_scan          -- Scans, vulnerabilities, FRS scores
forge_soc           -- Alerts, incidents, playbooks, detection rules
forge_redops        -- Pen tests, agents, findings, exploits
```

**Benefits:**
- Each product module owns its schema and migrations
- Cross-schema queries via PostgreSQL foreign data wrappers or application-level joins
- Independent scaling (read replicas per schema if needed)
- Clear data ownership boundaries

### 6.2 Shared Data Model -- Key Relationships

```
Asset (core) ──┬── Vulnerability (forgescan)
               ├── Alert (forgesoc)
               ├── PenTestFinding (forgeredops)
               └── ControlMapping (compliance)

Vulnerability ──┬── ControlMapping
                ├── PenTestFinding (validates exploitability)
                └── Alert (SOC detection of exploitation)

Finding ────────┬── ControlMapping
                └── POAMEntry (compliance)
```

---

## 7. RBAC Design

### 7.1 Unified Role Hierarchy

```
Platform Roles (cross-product):
├── Platform Admin         -- Full access to everything
├── Compliance Manager     -- Read all, write compliance
└── Auditor               -- Read-only across all modules

ForgeScan Roles:
├── Scan Administrator    -- Configure scans, manage policies
├── Vulnerability Manager -- Triage, assign, track vulns
└── Remediation Owner     -- Update vuln status for assigned assets

ForgeSOC Roles:
├── SOC Manager           -- Manage team, approve escalations
├── SOC Analyst (Tier 1)  -- Alert triage, initial investigation
├── SOC Analyst (Tier 2)  -- Deep investigation, threat hunting
└── Incident Responder    -- Execute playbooks, containment

ForgeRedOps Roles:
├── Red Team Lead         -- Configure pen tests, review findings
├── Pen Test Operator     -- Launch/monitor AI agents
└── Purple Team Analyst   -- Cross-reference offensive + defensive
```

### 7.2 Permission Model

Use attribute-based access control (ABAC) layered on RBAC:

```
Permission {
  product: "forgescan" | "forgesoc" | "forgeredops" | "core"
  resource: "assets" | "vulnerabilities" | "alerts" | "pentests" | ...
  action: "create" | "read" | "update" | "delete" | "execute"
  conditions: {
    site_ids?: string[]     // limit to specific sites
    criticality?: string[]  // only see critical assets
    classification?: string // only clearance-appropriate data
  }
}
```

---

## 8. Build Sequence Recommendation

### Phase 1: Foundation
1. `@forge/types` -- Shared TypeScript interfaces and enums
2. `@forge/event-bus` -- Event backbone (start with Redis Streams, migrate to Kafka later)
3. `@forge/asset-registry` -- Unified asset model + API
4. `@forge/gateway` -- API gateway with auth

### Phase 2: Core Services
5. `@forge/compliance-core` -- Control frameworks, mapping logic, POA&M generation
6. `@forge/integration-hub` -- Start with Jira + Slack connectors
7. `@forge/ui-shell` -- Design system, layout, auth UI

### Phase 3: First Product (ForgeScan)
8. `@forge/forgescan` -- Scan orchestrator, ingestion, FRS engine, discovery, ASM
9. ForgeScan UI views (dashboard, vulns, assets, scans, reports)

### Phase 4: Second Product (ForgeSOC)
10. `@forge/forgesoc` -- Detection engine, incident management, playbook engine
11. ForgeSOC UI views (SOC workbench, alerts, incidents, threat intel)

### Phase 5: Third Product (ForgeRedOps)
12. `@forge/forgeredops` -- AI agent framework, pen test controller
13. Individual agent implementations (web, API, cloud, network, identity)
14. ForgeRedOps UI views (pen test dashboard, findings, agent status)

### Phase 6: Cross-Product Integration
15. Cross-product event workflows (Section 4)
16. Unified executive dashboard across all products
17. Advanced ForgeML correlation (SOC + Scan + RedOps signals)

---

## 9. Key Design Decisions & Tradeoffs

### Decision 1: Monorepo vs Polyrepo
**Recommendation: Monorepo (Turborepo)**

| Factor | Monorepo | Polyrepo |
|---|---|---|
| Code sharing | Trivial (workspace packages) | Complex (publish + version + consume) |
| Refactoring | Atomic cross-package changes | Coordinated multi-repo PRs |
| CI/CD | One pipeline, selective builds | Multiple pipelines |
| Team autonomy | Lower (shared conventions) | Higher (independent velocity) |

Monorepo wins because the products share so much code. The overhead of package publishing across 3+ repos would slow development significantly.

### Decision 2: Microservices vs Modular Monolith
**Recommendation: Start as modular monolith, extract services as needed**

Deploy as a single application per product initially, with clean module boundaries. Extract to microservices only when:
- A module needs independent scaling (e.g., ForgeSOC ingestion at high log volume)
- A module needs different deployment cadence
- Team size requires independent deployability

This avoids premature distributed systems complexity while maintaining the option to split later.

### Decision 3: Event Bus Technology
**Recommendation: Redis Streams initially, Kafka when volume requires it**

Redis Streams provides adequate pub/sub for early stages and is already in the stack. Kafka is warranted when:
- Log ingestion exceeds 10K events/second (ForgeSOC at scale)
- Multi-day event replay is needed for investigation
- Consumer group complexity requires Kafka's guarantees

### Decision 4: AI Runtime
**Recommendation: Dual-mode (Claude API + Ollama)**

Already specified in both ForgeSOC and ForgeRedOps docs. Abstract behind a `@forge/ai-provider` interface:

```typescript
interface ForgeAIProvider {
  analyze(prompt: string, context: AnalysisContext): Promise<AIResult>
  classify(input: ClassificationInput): Promise<Classification>
  generate(template: string, variables: Record<string, unknown>): Promise<string>
}

// Implementations:
// CloudAIProvider -- Claude API (Cloudflare Workers AI Gateway)
// LocalAIProvider -- Ollama + Llama 3 (air-gapped environments)
```

---

## 10. Air-Gapped Deployment Considerations

Since ForgeRedOps specifies air-gapped capability for classified environments:

- All AI inference must work offline via Ollama + Llama 3
- No external API dependencies (Cloudflare Workers replaced by local Nginx + Node.js)
- All threat intel feeds must support offline bundle import
- Container images must be pre-built and transferred via approved media
- Database runs on-premises PostgreSQL (no D1)
- Object storage switches from R2/S3 to MinIO

The modular architecture supports this by making cloud services pluggable:

```typescript
// Cloud deployment
bind(StorageProvider).to(R2StorageProvider)
bind(DatabaseProvider).to(D1DatabaseProvider)
bind(AIProvider).to(ClaudeAIProvider)

// Air-gapped deployment
bind(StorageProvider).to(MinIOStorageProvider)
bind(DatabaseProvider).to(PostgreSQLProvider)
bind(AIProvider).to(OllamaAIProvider)
```

---

## 11. Summary of Recommendations

1. **Build a shared platform core first** -- Asset Registry, Compliance Core, Integration Hub, Event Bus, API Gateway, and UI Shell. This eliminates 60-70% of duplicated effort.

2. **Use a TypeScript monorepo with Turborepo** -- Shared types and utilities across all products; atomic refactoring; selective CI builds.

3. **Start as a modular monolith** -- Clean package boundaries but deployed as single applications. Extract microservices only when scaling demands it.

4. **Event-driven cross-product workflows** -- The event bus is the most valuable architectural investment. It enables automated Scan -> PenTest -> SOC -> Compliance chains.

5. **Schema-per-module database design** -- Single PostgreSQL cluster, separate schemas per product. Clear ownership, cross-schema queries when needed.

6. **Abstract AI and infrastructure providers** -- Interface-based design enables both cloud (Claude API, Cloudflare) and air-gapped (Ollama, MinIO) deployments from the same codebase.

7. **Build ForgeScan first** -- It provides the asset and vulnerability data that both ForgeSOC and ForgeRedOps consume. It is the foundational data source.

8. **Unified RBAC with ABAC extensions** -- Platform-wide roles for cross-product access, product-specific roles for domain operations, attribute conditions for site/classification filtering.
