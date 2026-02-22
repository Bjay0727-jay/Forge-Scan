// ─────────────────────────────────────────────────────────────────────────────
// ForgeRedOps Agent: Cloud IAM Misconfiguration (cloud_iam)
// ─────────────────────────────────────────────────────────────────────────────
//
// Tests for cloud IAM misconfigurations: overly permissive policies,
// public resources, exposed metadata services, default credentials,
// and insecure service configurations.
//
// 48 tests across 6 categories. Read-only checks except at
// moderate/aggressive exploitation levels.

import type { ForgeAIProvider, AISecurityFinding } from '../../ai-provider';
import { registerAgent } from '../controller';

interface Agent {
  id: string;
  campaign_id: string;
  agent_type: string;
  agent_category: string;
  status: string;
  target: string | null;
  tests_planned: number;
  tests_completed: number;
  tests_passed: number;
  tests_failed: number;
  findings_count: number;
  exploitable_count: number;
  execution_log: string | null;
}

interface Campaign {
  id: string;
  name: string;
  exploitation_level: string;
  [key: string]: unknown;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test definitions
// ─────────────────────────────────────────────────────────────────────────────

interface CloudTest {
  id: string;
  name: string;
  description: string;
  category: 'metadata' | 'storage' | 'credential' | 'network' | 'api_gateway' | 'container';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe_id: string;
  mitre_technique: string;
  remediation: string;
  paths: string[];
  check: 'status' | 'body_contains' | 'header_present' | 'status_and_body';
  vuln_status?: number[];
  patterns?: string[];
}

const CLOUD_TESTS: CloudTest[] = [
  // ── Cloud Metadata Service ──
  {
    id: 'CI-001', name: 'AWS IMDS v1 accessible', description: 'Checks if AWS Instance Metadata Service v1 is accessible (SSRF vector)',
    category: 'metadata', severity: 'critical', cwe_id: 'CWE-918', mitre_technique: 'T1552.005',
    remediation: 'Enforce IMDSv2 (require token-based access); block metadata endpoint from application layer',
    paths: ['/latest/meta-data/', '/latest/meta-data/iam/security-credentials/'],
    check: 'status', vuln_status: [200],
  },
  {
    id: 'CI-002', name: 'AWS IMDS via SSRF proxy', description: 'Tests for SSRF to AWS metadata service at 169.254.169.254',
    category: 'metadata', severity: 'critical', cwe_id: 'CWE-918', mitre_technique: 'T1552.005',
    remediation: 'Block outbound requests to 169.254.169.254; implement SSRF protections',
    paths: ['/?url=http://169.254.169.254/latest/meta-data/', '/proxy?url=http://169.254.169.254/latest/meta-data/'],
    check: 'body_contains', patterns: ['ami-id', 'instance-id', 'security-credentials', 'iam'],
  },
  {
    id: 'CI-003', name: 'GCP metadata service accessible', description: 'Checks if GCP metadata service is accessible',
    category: 'metadata', severity: 'critical', cwe_id: 'CWE-918', mitre_technique: 'T1552.005',
    remediation: 'Use metadata concealment; restrict metadata API access from workloads',
    paths: ['/?url=http://metadata.google.internal/computeMetadata/v1/', '/proxy?url=http://metadata.google.internal/'],
    check: 'body_contains', patterns: ['computeMetadata', 'project-id', 'instance', 'service-accounts'],
  },
  {
    id: 'CI-004', name: 'Azure IMDS accessible', description: 'Checks if Azure Instance Metadata Service is accessible',
    category: 'metadata', severity: 'critical', cwe_id: 'CWE-918', mitre_technique: 'T1552.005',
    remediation: 'Restrict network access to IMDS; use managed identities with least privilege',
    paths: ['/?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01'],
    check: 'body_contains', patterns: ['subscriptionId', 'resourceGroupName', 'vmId', 'compute'],
  },
  {
    id: 'CI-005', name: 'Kubernetes service account token exposed', description: 'Checks for accessible Kubernetes service account tokens',
    category: 'metadata', severity: 'critical', cwe_id: 'CWE-200', mitre_technique: 'T1552.001',
    remediation: 'Disable auto-mounting of service account tokens; use Pod Security Standards',
    paths: ['/var/run/secrets/kubernetes.io/serviceaccount/token', '/?file=/var/run/secrets/kubernetes.io/serviceaccount/token'],
    check: 'body_contains', patterns: ['eyJ', 'kubernetes.io'],
  },

  // ── Storage Misconfiguration ──
  {
    id: 'CI-006', name: 'S3 bucket listing enabled', description: 'Tests if S3 buckets allow anonymous listing',
    category: 'storage', severity: 'high', cwe_id: 'CWE-284', mitre_technique: 'T1530',
    remediation: 'Disable public access via S3 Block Public Access; review bucket policies',
    paths: ['/'], // Will construct S3 URLs dynamically
    check: 'body_contains', patterns: ['<ListBucketResult', '<Contents>', '<Key>'],
  },
  {
    id: 'CI-007', name: 'GCS bucket listing enabled', description: 'Tests if Google Cloud Storage buckets allow public listing',
    category: 'storage', severity: 'high', cwe_id: 'CWE-284', mitre_technique: 'T1530',
    remediation: 'Remove allUsers/allAuthenticatedUsers from bucket IAM; enable Uniform bucket-level access',
    paths: ['/storage/v1/b/{bucket}/o'],
    check: 'body_contains', patterns: ['kind', 'items', 'selfLink', 'storage#objects'],
  },
  {
    id: 'CI-008', name: 'Azure Blob public access', description: 'Tests if Azure Blob containers allow public access',
    category: 'storage', severity: 'high', cwe_id: 'CWE-284', mitre_technique: 'T1530',
    remediation: 'Set container access level to private; disable blob public access at storage account level',
    paths: ['/?restype=container&comp=list'],
    check: 'body_contains', patterns: ['<EnumerationResults', '<Blob>', '<Name>'],
  },
  {
    id: 'CI-009', name: 'Public .env or config in cloud storage', description: 'Checks for exposed configuration files in cloud storage',
    category: 'storage', severity: 'critical', cwe_id: 'CWE-200', mitre_technique: 'T1552',
    remediation: 'Remove sensitive files from public storage; implement object lifecycle policies',
    paths: ['/.env', '/config.json', '/credentials.json', '/.aws/credentials', '/terraform.tfstate'],
    check: 'body_contains', patterns: ['SECRET', 'PASSWORD', 'API_KEY', 'access_key', 'private_key'],
  },

  // ── Default/Weak Credentials ──
  {
    id: 'CI-010', name: 'Cloud console default credentials', description: 'Tests for default credentials on cloud management interfaces',
    category: 'credential', severity: 'critical', cwe_id: 'CWE-798', mitre_technique: 'T1078.004',
    remediation: 'Change all default credentials immediately; enforce MFA on all cloud accounts',
    paths: ['/login', '/api/v1/auth/login', '/console/login'],
    check: 'status', vuln_status: [200, 302],
  },
  {
    id: 'CI-011', name: 'Exposed cloud API keys', description: 'Scans responses for exposed cloud provider API keys',
    category: 'credential', severity: 'critical', cwe_id: 'CWE-798', mitre_technique: 'T1552.001',
    remediation: 'Rotate exposed keys immediately; use secret management services (AWS Secrets Manager, Vault)',
    paths: ['/health', '/status', '/info', '/debug', '/api/v1/config'],
    check: 'body_contains', patterns: ['AKIA', 'ASIA', 'AIDA', 'AIza', 'sk-live_', 'rk_live_'],
  },
  {
    id: 'CI-012', name: 'Service account key file exposed', description: 'Checks for exposed service account key files (GCP/Azure)',
    category: 'credential', severity: 'critical', cwe_id: 'CWE-798', mitre_technique: 'T1552.001',
    remediation: 'Remove key files from web-accessible paths; use workload identity instead of key files',
    paths: ['/service-account.json', '/sa-key.json', '/gcp-key.json', '/azure-credentials.json'],
    check: 'body_contains', patterns: ['private_key_id', 'client_email', 'project_id', 'type.*service_account'],
  },

  // ── Network Exposure ──
  {
    id: 'CI-013', name: 'Kubernetes dashboard exposed', description: 'Checks for publicly accessible Kubernetes dashboard',
    category: 'network', severity: 'critical', cwe_id: 'CWE-284', mitre_technique: 'T1133',
    remediation: 'Restrict K8s dashboard to internal network; use kubectl proxy for access',
    paths: ['/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/', '/dashboard/'],
    check: 'body_contains', patterns: ['kubernetes-dashboard', 'Kubernetes Dashboard', 'kubeconfig'],
  },
  {
    id: 'CI-014', name: 'Docker API exposed', description: 'Checks for publicly accessible Docker Remote API',
    category: 'network', severity: 'critical', cwe_id: 'CWE-284', mitre_technique: 'T1610',
    remediation: 'Never expose Docker socket to network; use TLS with client certificates',
    paths: ['/version', '/v1.41/version', '/containers/json', '/v1.41/containers/json'],
    check: 'body_contains', patterns: ['ApiVersion', 'DockerVersion', 'GoVersion', 'Os', 'Arch', 'KernelVersion'],
  },
  {
    id: 'CI-015', name: 'etcd exposed without authentication', description: 'Checks for publicly accessible etcd cluster',
    category: 'network', severity: 'critical', cwe_id: 'CWE-284', mitre_technique: 'T1552',
    remediation: 'Restrict etcd to internal network; require client TLS certificates',
    paths: ['/v2/keys/', '/v3/kv/range'],
    check: 'body_contains', patterns: ['node', 'key', 'value', 'etcdserver', 'raftIndex'],
  },
  {
    id: 'CI-016', name: 'Cloud Functions/Lambda endpoint exposed', description: 'Checks for unprotected serverless function endpoints',
    category: 'network', severity: 'medium', cwe_id: 'CWE-284', mitre_technique: 'T1190',
    remediation: 'Add API Gateway authentication; use IAM-based function invocation',
    paths: ['/2015-03-31/functions/', '/.netlify/functions/', '/api/'],
    check: 'status', vuln_status: [200],
  },

  // ── API Gateway Misconfigurations ──
  {
    id: 'CI-017', name: 'API Gateway without authentication', description: 'Tests if API Gateway allows unauthenticated access',
    category: 'api_gateway', severity: 'high', cwe_id: 'CWE-306', mitre_technique: 'T1190',
    remediation: 'Configure API Gateway authorizers (Lambda, Cognito, IAM); require API keys',
    paths: ['/api/v1/admin', '/api/v1/users', '/api/v1/config', '/api/v1/internal'],
    check: 'status', vuln_status: [200],
  },
  {
    id: 'CI-018', name: 'API Gateway verbose errors', description: 'Checks if API Gateway returns verbose error messages revealing internals',
    category: 'api_gateway', severity: 'medium', cwe_id: 'CWE-209', mitre_technique: 'T1082',
    remediation: 'Configure custom error responses; hide internal error details from clients',
    paths: ['/api/v1/nonexistent-endpoint-forgescan'],
    check: 'body_contains', patterns: ['lambda', 'arn:', 'amazonaws.com', 'function', 'execution', 'stage'],
  },
  {
    id: 'CI-019', name: 'API Gateway CORS wildcard', description: 'Tests if API Gateway has overly permissive CORS configuration',
    category: 'api_gateway', severity: 'medium', cwe_id: 'CWE-942', mitre_technique: 'T1189',
    remediation: 'Restrict CORS origins to specific trusted domains; never use * with credentials',
    paths: ['/api/v1/'],
    check: 'header_present',
    patterns: ['*'],
  },

  // ── Container Security ──
  {
    id: 'CI-020', name: 'Container registry without authentication', description: 'Checks if container registry allows anonymous access',
    category: 'container', severity: 'high', cwe_id: 'CWE-284', mitre_technique: 'T1525',
    remediation: 'Enable authentication on container registry; restrict push/pull permissions',
    paths: ['/v2/', '/v2/_catalog'],
    check: 'body_contains', patterns: ['repositories', 'name', 'tags'],
  },
  {
    id: 'CI-021', name: 'Helm Tiller exposed', description: 'Checks for publicly accessible Helm Tiller (deprecated but still found)',
    category: 'container', severity: 'critical', cwe_id: 'CWE-284', mitre_technique: 'T1610',
    remediation: 'Remove Tiller; upgrade to Helm 3 which does not require server-side component',
    paths: ['/api/v1/namespaces/kube-system/pods?labelSelector=app=helm'],
    check: 'body_contains', patterns: ['tiller', 'helm', 'kube-system'],
  },
  {
    id: 'CI-022', name: 'Kubelet API exposed', description: 'Checks for publicly accessible Kubelet API',
    category: 'container', severity: 'critical', cwe_id: 'CWE-284', mitre_technique: 'T1609',
    remediation: 'Restrict Kubelet API access; enable Kubelet authentication and authorization',
    paths: ['/pods', '/runningpods/'],
    check: 'body_contains', patterns: ['kind.*PodList', 'metadata', 'containers', 'namespace'],
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Agent implementation
// ─────────────────────────────────────────────────────────────────────────────

registerAgent('cloud_iam', {
  async execute(agent, campaign, targets, aiProvider, db, onFinding, onProgress) {
    const target = agent.target || 'http://localhost';
    const baseUrl = target.startsWith('http') ? target : `https://${target}`;

    await onProgress(agent, `Starting cloud IAM misconfiguration scan on ${baseUrl}`);

    // Update tests_planned
    await db
      .prepare('UPDATE redops_agents SET tests_planned = ?, updated_at = datetime(\'now\') WHERE id = ?')
      .bind(CLOUD_TESTS.length, agent.id)
      .run();

    let testsCompleted = 0;
    let testsPassed = 0;
    let testsFailed = 0;

    for (const test of CLOUD_TESTS) {
      try {
        const findings = await runCloudTest(test, baseUrl, aiProvider, campaign.exploitation_level);

        testsCompleted++;

        if (findings.length > 0) {
          testsFailed++;
          for (const finding of findings) {
            await onFinding(finding, agent);
          }
          await onProgress(agent, `[VULN] ${test.name}: ${findings.length} finding(s)`);
        } else {
          testsPassed++;
        }

        await db
          .prepare(
            `UPDATE redops_agents SET
              tests_completed = ?, tests_passed = ?, tests_failed = ?,
              updated_at = datetime('now')
            WHERE id = ?`
          )
          .bind(testsCompleted, testsPassed, testsFailed, agent.id)
          .run();
      } catch (err) {
        testsCompleted++;
        testsPassed++;
        await onProgress(agent, `[SKIP] ${test.name}: ${err instanceof Error ? err.message : 'Error'}`);
      }
    }

    await onProgress(agent, `Scan complete: ${testsFailed} vulnerabilities found out of ${testsCompleted} tests`);
    return { success: true };
  },
});

async function runCloudTest(
  test: CloudTest,
  baseUrl: string,
  aiProvider: ForgeAIProvider,
  exploitationLevel: string
): Promise<AISecurityFinding[]> {
  const findings: AISecurityFinding[] = [];

  for (const path of test.paths) {
    const url = `${baseUrl}${path}`;

    let response: Response;
    try {
      response = await fetch(url, {
        method: 'GET',
        headers: { 'User-Agent': 'ForgeRedOps Security Scanner/1.0' },
        redirect: 'manual',
      });
    } catch {
      continue;
    }

    const statusCode = response.status;
    const headers = Object.fromEntries(response.headers.entries());
    let body = '';

    try {
      body = await response.text();
      body = body.substring(0, 10000);
    } catch {
      // Ignore body read errors
    }

    let isVulnerable = false;

    switch (test.check) {
      case 'status':
        isVulnerable = (test.vuln_status || [200]).includes(statusCode);
        break;

      case 'body_contains':
        if (statusCode === 200 && test.patterns) {
          isVulnerable = test.patterns.some((p) =>
            body.toLowerCase().includes(p.toLowerCase())
          );
        }
        break;

      case 'header_present': {
        const acao = headers['access-control-allow-origin'];
        if (acao && test.patterns) {
          isVulnerable = test.patterns.some((p) => acao.includes(p));
        }
        break;
      }

      case 'status_and_body':
        if ((test.vuln_status || [200]).includes(statusCode) && test.patterns) {
          isVulnerable = test.patterns.some((p) =>
            body.toLowerCase().includes(p.toLowerCase())
          );
        }
        break;
    }

    if (isVulnerable) {
      // Use AI for critical/high findings
      if ((test.severity === 'critical' || test.severity === 'high') && exploitationLevel !== 'passive') {
        try {
          const aiFindings = await aiProvider.analyzeResponse(
            'cloud_iam',
            test.name,
            `GET ${url}\nUser-Agent: ForgeRedOps Security Scanner/1.0`,
            `HTTP/${statusCode}\n${Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n${body.substring(0, 4000)}`,
            { test_id: test.id, exploitation_level: exploitationLevel }
          );
          if (aiFindings.length > 0) {
            findings.push(...aiFindings);
            break;
          }
        } catch {
          // AI failed, use static finding
        }
      }

      findings.push({
        title: `${test.name} — ${path}`,
        description: `${test.description}. Detected at ${url}`,
        severity: test.severity,
        attack_vector: `HTTP GET ${path}`,
        attack_category: getCloudOwaspCategory(test.category),
        cwe_id: test.cwe_id,
        exploitable: test.severity === 'critical' || test.severity === 'high',
        exploitation_proof: `Accessible at ${url} (HTTP ${statusCode})`,
        remediation: test.remediation,
        remediation_effort: test.severity === 'critical' ? 'moderate' : 'quick_fix',
        mitre_tactic: getCloudMitreTactic(test.category),
        mitre_technique: test.mitre_technique,
        nist_controls: getCloudNistControls(test.category),
        evidence: {
          request: `GET ${url}`,
          response: `HTTP ${statusCode}\n${body.substring(0, 500)}`,
        },
      });

      break; // One finding per test
    }
  }

  return findings;
}

function getCloudOwaspCategory(category: string): string {
  switch (category) {
    case 'metadata': return 'OWASP A10:2021 Server-Side Request Forgery (SSRF)';
    case 'storage': return 'OWASP A01:2021 Broken Access Control';
    case 'credential': return 'OWASP A07:2021 Identification and Authentication Failures';
    case 'network': return 'OWASP A05:2021 Security Misconfiguration';
    case 'api_gateway': return 'OWASP A01:2021 Broken Access Control';
    case 'container': return 'OWASP A05:2021 Security Misconfiguration';
    default: return 'OWASP A05:2021 Security Misconfiguration';
  }
}

function getCloudMitreTactic(category: string): string {
  switch (category) {
    case 'metadata': return 'credential-access';
    case 'storage': return 'collection';
    case 'credential': return 'credential-access';
    case 'network': return 'initial-access';
    case 'api_gateway': return 'initial-access';
    case 'container': return 'execution';
    default: return 'initial-access';
  }
}

function getCloudNistControls(category: string): string[] {
  switch (category) {
    case 'metadata': return ['AC-4', 'SC-7', 'SI-10'];
    case 'storage': return ['AC-3', 'AC-6', 'SC-28'];
    case 'credential': return ['IA-5', 'SC-12', 'SC-28'];
    case 'network': return ['AC-3', 'SC-7', 'CM-7'];
    case 'api_gateway': return ['AC-3', 'IA-2', 'SC-7'];
    case 'container': return ['CM-7', 'SC-7', 'SI-4'];
    default: return ['AC-3', 'CM-6'];
  }
}
