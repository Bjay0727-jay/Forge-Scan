// ─────────────────────────────────────────────────────────────────────────────
// Compliance Core — CWE/Finding-to-Control Mapping
// Enables auto-POA&M generation for both ForgeScan and ForgeRedOps findings
// ─────────────────────────────────────────────────────────────────────────────

export interface ControlMapping {
  framework: string;       // 'nist-800-53' | 'cis-v8' | 'pci-dss' | 'hipaa'
  control_id: string;
  control_name: string;
  relevance: 'primary' | 'secondary';
}

export interface POAMEntry {
  id: string;
  finding_title: string;
  weakness: string;         // CWE or description
  severity: string;
  controls: ControlMapping[];
  remediation: string;
  remediation_effort: string;
  scheduled_completion: string;
  status: 'open' | 'in_progress' | 'completed' | 'delayed';
  milestones: string[];
  created_at: string;
}

// ─── CWE to NIST 800-53 Mapping ─────────────────────────────────────────────

const CWE_TO_NIST: Record<string, { control_ids: string[]; relevance: 'primary' | 'secondary' }[]> = {
  // Injection flaws
  'CWE-89':  [{ control_ids: ['SI-10', 'SI-2'], relevance: 'primary' }],   // SQL Injection
  'CWE-79':  [{ control_ids: ['SI-10', 'SI-2'], relevance: 'primary' }],   // XSS
  'CWE-78':  [{ control_ids: ['SI-10', 'SI-3'], relevance: 'primary' }],   // OS Command Injection
  'CWE-94':  [{ control_ids: ['SI-10', 'SI-3'], relevance: 'primary' }],   // Code Injection
  'CWE-917': [{ control_ids: ['SI-10'], relevance: 'primary' }],           // Server-Side Template Injection

  // Authentication/Authorization
  'CWE-287': [{ control_ids: ['IA-2', 'IA-5', 'AC-3'], relevance: 'primary' }],  // Improper Auth
  'CWE-306': [{ control_ids: ['IA-2', 'AC-3'], relevance: 'primary' }],           // Missing Auth
  'CWE-862': [{ control_ids: ['AC-3', 'AC-6'], relevance: 'primary' }],           // Missing AuthZ
  'CWE-863': [{ control_ids: ['AC-3', 'AC-6'], relevance: 'primary' }],           // Incorrect AuthZ
  'CWE-798': [{ control_ids: ['IA-5', 'SC-13'], relevance: 'primary' }],          // Hardcoded Credentials
  'CWE-521': [{ control_ids: ['IA-5'], relevance: 'primary' }],                   // Weak Password
  'CWE-307': [{ control_ids: ['AC-7'], relevance: 'primary' }],                   // Brute Force
  'CWE-384': [{ control_ids: ['IA-2', 'SC-8'], relevance: 'primary' }],           // Session Fixation

  // Cryptography
  'CWE-327': [{ control_ids: ['SC-13', 'SC-8'], relevance: 'primary' }],   // Broken Crypto
  'CWE-326': [{ control_ids: ['SC-13'], relevance: 'primary' }],           // Weak Encryption
  'CWE-311': [{ control_ids: ['SC-8', 'SC-13'], relevance: 'primary' }],   // Missing Encryption

  // Configuration
  'CWE-16':  [{ control_ids: ['CM-6', 'CM-7'], relevance: 'primary' }],    // Configuration
  'CWE-200': [{ control_ids: ['CM-7', 'SI-5'], relevance: 'primary' }],    // Info Exposure
  'CWE-209': [{ control_ids: ['CM-7', 'SI-4'], relevance: 'primary' }],    // Error Info Exposure
  'CWE-532': [{ control_ids: ['AU-3', 'CM-6'], relevance: 'primary' }],    // Info in Logs

  // Cloud/IAM
  'CWE-269': [{ control_ids: ['AC-6', 'AC-2'], relevance: 'primary' }],    // Privilege Management
  'CWE-250': [{ control_ids: ['AC-6'], relevance: 'primary' }],            // Unnecessary Privileges
};

// ─── CWE to CIS Controls Mapping ────────────────────────────────────────────

const CWE_TO_CIS: Record<string, string[]> = {
  'CWE-89':  ['CIS-16'],                    // SQL Injection -> App Security
  'CWE-79':  ['CIS-16', 'CIS-9'],           // XSS -> App Security, Web Protections
  'CWE-78':  ['CIS-16'],                    // OS Command Injection
  'CWE-287': ['CIS-5', 'CIS-6'],            // Improper Auth -> Account/Access Mgmt
  'CWE-306': ['CIS-5', 'CIS-6'],            // Missing Auth
  'CWE-862': ['CIS-6'],                     // Missing AuthZ
  'CWE-798': ['CIS-5'],                     // Hardcoded Credentials
  'CWE-521': ['CIS-5'],                     // Weak Password
  'CWE-327': ['CIS-3'],                     // Broken Crypto -> Data Protection
  'CWE-16':  ['CIS-4'],                     // Config Issues -> Secure Config
  'CWE-200': ['CIS-4', 'CIS-3'],            // Info Exposure
  'CWE-269': ['CIS-5', 'CIS-6'],            // Privilege Issues
};

// ─── NIST control lookup ─────────────────────────────────────────────────────

const NIST_CONTROLS: Record<string, string> = {
  'AC-2': 'Account Management',
  'AC-3': 'Access Enforcement',
  'AC-6': 'Least Privilege',
  'AC-7': 'Unsuccessful Logon Attempts',
  'AU-3': 'Content of Audit Records',
  'CM-6': 'Configuration Settings',
  'CM-7': 'Least Functionality',
  'IA-2': 'Identification and Authentication',
  'IA-5': 'Authenticator Management',
  'IR-4': 'Incident Handling',
  'RA-5': 'Vulnerability Monitoring and Scanning',
  'SC-7': 'Boundary Protection',
  'SC-8': 'Transmission Confidentiality and Integrity',
  'SC-13': 'Cryptographic Protection',
  'SI-2': 'Flaw Remediation',
  'SI-3': 'Malicious Code Protection',
  'SI-4': 'System Monitoring',
  'SI-5': 'Security Alerts and Advisories',
  'SI-10': 'Information Input Validation',
};

const CIS_CONTROLS: Record<string, string> = {
  'CIS-3': 'Data Protection',
  'CIS-4': 'Secure Configuration',
  'CIS-5': 'Account Management',
  'CIS-6': 'Access Control Management',
  'CIS-7': 'Continuous Vulnerability Management',
  'CIS-8': 'Audit Log Management',
  'CIS-9': 'Email and Web Browser Protections',
  'CIS-13': 'Network Monitoring and Defense',
  'CIS-16': 'Application Software Security',
};

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Map a finding (by CWE or NIST controls list) to all relevant compliance controls.
 */
export function mapFindingToControls(finding: {
  cwe_id?: string;
  nist_controls?: string[];
  attack_category?: string;
}): ControlMapping[] {
  const mappings: ControlMapping[] = [];
  const seen = new Set<string>();

  // Map via CWE
  if (finding.cwe_id) {
    const nistMappings = mapCWEToNISTControls(finding.cwe_id);
    for (const m of nistMappings) {
      const key = `nist-${m.control_id}`;
      if (!seen.has(key)) {
        seen.add(key);
        mappings.push(m);
      }
    }

    const cisMappings = mapCWEToCISControls(finding.cwe_id);
    for (const m of cisMappings) {
      const key = `cis-${m.control_id}`;
      if (!seen.has(key)) {
        seen.add(key);
        mappings.push(m);
      }
    }
  }

  // Map via explicit NIST controls (e.g., from RedOps agents)
  if (finding.nist_controls) {
    for (const controlId of finding.nist_controls) {
      const key = `nist-${controlId}`;
      if (!seen.has(key)) {
        seen.add(key);
        mappings.push({
          framework: 'nist-800-53',
          control_id: controlId,
          control_name: NIST_CONTROLS[controlId] || controlId,
          relevance: 'primary',
        });
      }
    }
  }

  // Default: always map to RA-5 (Vulnerability Scanning) for any finding
  if (!seen.has('nist-RA-5')) {
    mappings.push({
      framework: 'nist-800-53',
      control_id: 'RA-5',
      control_name: 'Vulnerability Monitoring and Scanning',
      relevance: 'secondary',
    });
  }

  return mappings;
}

/**
 * Map a CWE to NIST 800-53 controls.
 */
export function mapCWEToNISTControls(cweId: string): ControlMapping[] {
  const mappings: ControlMapping[] = [];
  const cweEntries = CWE_TO_NIST[cweId];

  if (cweEntries) {
    for (const entry of cweEntries) {
      for (const controlId of entry.control_ids) {
        mappings.push({
          framework: 'nist-800-53',
          control_id: controlId,
          control_name: NIST_CONTROLS[controlId] || controlId,
          relevance: entry.relevance,
        });
      }
    }
  }

  return mappings;
}

/**
 * Map a CWE to CIS Controls.
 */
export function mapCWEToCISControls(cweId: string): ControlMapping[] {
  const controlIds = CWE_TO_CIS[cweId] || [];
  return controlIds.map((controlId) => ({
    framework: 'cis-v8',
    control_id: controlId,
    control_name: CIS_CONTROLS[controlId] || controlId,
    relevance: 'primary' as const,
  }));
}

/**
 * Generate a POA&M entry from a finding.
 * Used by both ForgeScan compliance reports and RedOps auto-POA&M.
 */
export function generatePOAMEntry(finding: {
  id: string;
  title: string;
  cwe_id?: string;
  severity: string;
  remediation?: string;
  remediation_effort?: string;
  nist_controls?: string[];
}): POAMEntry {
  const controls = mapFindingToControls(finding);

  // Calculate scheduled completion based on severity
  const daysToRemediate: Record<string, number> = {
    critical: 15,
    high: 30,
    medium: 90,
    low: 180,
    info: 365,
  };
  const days = daysToRemediate[finding.severity] || 90;
  const scheduledDate = new Date();
  scheduledDate.setDate(scheduledDate.getDate() + days);

  return {
    id: crypto.randomUUID(),
    finding_title: finding.title,
    weakness: finding.cwe_id || 'Unclassified',
    severity: finding.severity,
    controls,
    remediation: finding.remediation || 'Pending assessment',
    remediation_effort: finding.remediation_effort || 'moderate',
    scheduled_completion: scheduledDate.toISOString().split('T')[0],
    status: 'open',
    milestones: [
      'Identify affected systems',
      'Develop remediation plan',
      'Implement fix',
      'Verify remediation',
    ],
    created_at: new Date().toISOString(),
  };
}
