// Compliance Mapping Service
// Manages compliance frameworks, control seeding, and gap analysis

// --- Framework definitions ---

interface ControlDef {
  control_id: string;
  name: string;
  description: string;
  family: string;
  level?: string;
}

interface FrameworkDef {
  name: string;
  short_name: string;
  version: string;
  description: string;
  controls: ControlDef[];
}

const FRAMEWORKS: FrameworkDef[] = [
  // -------------------------------------------------------
  // NIST 800-53 Rev. 5
  // -------------------------------------------------------
  {
    name: 'NIST 800-53 Rev. 5',
    short_name: 'nist-800-53',
    version: 'Rev. 5',
    description: 'Security and privacy controls for federal information systems and organizations.',
    controls: [
      // Access Control (AC)
      { control_id: 'AC-1', name: 'Policy and Procedures', description: 'Develop, document, and disseminate access control policies and procedures.', family: 'Access Control', level: 'low' },
      { control_id: 'AC-2', name: 'Account Management', description: 'Manage system accounts including establishing, activating, modifying, reviewing, disabling, and removing accounts.', family: 'Access Control', level: 'low' },
      { control_id: 'AC-3', name: 'Access Enforcement', description: 'Enforce approved authorizations for logical access to information and system resources.', family: 'Access Control', level: 'low' },
      { control_id: 'AC-6', name: 'Least Privilege', description: 'Employ the principle of least privilege allowing only authorized accesses necessary to accomplish assigned tasks.', family: 'Access Control', level: 'moderate' },
      { control_id: 'AC-7', name: 'Unsuccessful Logon Attempts', description: 'Enforce a limit of consecutive invalid logon attempts by a user and take action when the limit is exceeded.', family: 'Access Control', level: 'low' },
      // Audit and Accountability (AU)
      { control_id: 'AU-2', name: 'Event Logging', description: 'Identify the types of events that the system is capable of logging in support of the audit function.', family: 'Audit and Accountability', level: 'low' },
      { control_id: 'AU-3', name: 'Content of Audit Records', description: 'Ensure audit records contain information that establishes what occurred, when, where, the source, and the outcome.', family: 'Audit and Accountability', level: 'low' },
      { control_id: 'AU-6', name: 'Audit Record Review', description: 'Review and analyze system audit records for indications of inappropriate or unusual activity.', family: 'Audit and Accountability', level: 'low' },
      // Configuration Management (CM)
      { control_id: 'CM-2', name: 'Baseline Configuration', description: 'Develop, document, and maintain a current baseline configuration of the information system.', family: 'Configuration Management', level: 'low' },
      { control_id: 'CM-6', name: 'Configuration Settings', description: 'Establish and document mandatory configuration settings for IT products using security configuration checklists.', family: 'Configuration Management', level: 'low' },
      { control_id: 'CM-7', name: 'Least Functionality', description: 'Configure the system to provide only essential capabilities and restrict the use of prohibited or restricted functions.', family: 'Configuration Management', level: 'low' },
      // Identification and Authentication (IA)
      { control_id: 'IA-2', name: 'Identification and Authentication', description: 'Uniquely identify and authenticate organizational users or processes acting on behalf of users.', family: 'Identification and Authentication', level: 'low' },
      { control_id: 'IA-5', name: 'Authenticator Management', description: 'Manage information system authenticators by verifying identity before distributing initial authenticators.', family: 'Identification and Authentication', level: 'low' },
      // Incident Response (IR)
      { control_id: 'IR-4', name: 'Incident Handling', description: 'Implement an incident handling capability for security incidents including preparation, detection, analysis, containment, and recovery.', family: 'Incident Response', level: 'low' },
      { control_id: 'IR-5', name: 'Incident Monitoring', description: 'Track and document security incidents on an ongoing basis.', family: 'Incident Response', level: 'low' },
      { control_id: 'IR-6', name: 'Incident Reporting', description: 'Require personnel to report suspected security incidents to the organizational incident response capability.', family: 'Incident Response', level: 'low' },
      // Risk Assessment (RA)
      { control_id: 'RA-3', name: 'Risk Assessment', description: 'Conduct assessments of risk including the likelihood and impact of unauthorized access, use, disclosure, or disruption.', family: 'Risk Assessment', level: 'low' },
      { control_id: 'RA-5', name: 'Vulnerability Monitoring and Scanning', description: 'Monitor and scan for vulnerabilities in the system and hosted applications on an ongoing basis.', family: 'Risk Assessment', level: 'low' },
      // System and Communications Protection (SC)
      { control_id: 'SC-7', name: 'Boundary Protection', description: 'Monitor and control communications at the external managed interfaces of the system and at key internal boundaries.', family: 'System and Communications Protection', level: 'low' },
      { control_id: 'SC-8', name: 'Transmission Confidentiality and Integrity', description: 'Protect the confidentiality and integrity of transmitted information using encryption.', family: 'System and Communications Protection', level: 'moderate' },
      { control_id: 'SC-13', name: 'Cryptographic Protection', description: 'Determine the cryptographic uses required and implement the types of cryptography needed for each use.', family: 'System and Communications Protection', level: 'low' },
      // System and Information Integrity (SI)
      { control_id: 'SI-2', name: 'Flaw Remediation', description: 'Identify, report, and correct system flaws in a timely manner.', family: 'System and Information Integrity', level: 'low' },
      { control_id: 'SI-3', name: 'Malicious Code Protection', description: 'Implement malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code.', family: 'System and Information Integrity', level: 'low' },
      { control_id: 'SI-4', name: 'System Monitoring', description: 'Monitor the system to detect attacks and indicators of potential attacks and unauthorized connections.', family: 'System and Information Integrity', level: 'low' },
      { control_id: 'SI-5', name: 'Security Alerts and Advisories', description: 'Receive security alerts, advisories, and directives from external organizations and disseminate to appropriate personnel.', family: 'System and Information Integrity', level: 'low' },
    ],
  },

  // -------------------------------------------------------
  // CIS Controls v8
  // -------------------------------------------------------
  {
    name: 'CIS Controls v8',
    short_name: 'cis-v8',
    version: '8.0',
    description: 'Prioritized set of actions to protect organizations and data from known cyber-attack vectors.',
    controls: [
      { control_id: 'CIS-1', name: 'Inventory and Control of Enterprise Assets', description: 'Actively manage all enterprise assets connected to the infrastructure to accurately know the totality of assets that need to be monitored and protected.', family: 'Asset Management', level: 'low' },
      { control_id: 'CIS-2', name: 'Inventory and Control of Software Assets', description: 'Actively manage all software on the network so only authorized software is installed and can execute.', family: 'Asset Management', level: 'low' },
      { control_id: 'CIS-3', name: 'Data Protection', description: 'Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.', family: 'Data Protection', level: 'low' },
      { control_id: 'CIS-4', name: 'Secure Configuration of Enterprise Assets and Software', description: 'Establish and maintain secure configurations for enterprise assets and software.', family: 'Configuration Management', level: 'low' },
      { control_id: 'CIS-5', name: 'Account Management', description: 'Use processes and tools to assign and manage authorization to credentials for user and service accounts.', family: 'Identity and Access', level: 'low' },
      { control_id: 'CIS-6', name: 'Access Control Management', description: 'Use processes and tools to create, assign, manage, and revoke access credentials and privileges for user and service accounts.', family: 'Identity and Access', level: 'low' },
      { control_id: 'CIS-7', name: 'Continuous Vulnerability Management', description: 'Continuously assess and track vulnerabilities on all enterprise assets to remediate and minimize the window of opportunity for attackers.', family: 'Vulnerability Management', level: 'low' },
      { control_id: 'CIS-8', name: 'Audit Log Management', description: 'Collect, alert, review, and retain audit logs of events that could help detect, understand, or recover from an attack.', family: 'Logging and Monitoring', level: 'low' },
      { control_id: 'CIS-9', name: 'Email and Web Browser Protections', description: 'Improve protections and detections of threats from email and web vectors as these are opportunities for attackers to manipulate human behavior.', family: 'Application Security', level: 'moderate' },
      { control_id: 'CIS-10', name: 'Malware Defenses', description: 'Prevent or control the installation, spread, and execution of malicious applications, code, or scripts.', family: 'Malware Defense', level: 'low' },
      { control_id: 'CIS-11', name: 'Data Recovery', description: 'Establish and maintain data recovery practices sufficient to restore in-scope enterprise assets to a pre-incident and trusted state.', family: 'Data Recovery', level: 'low' },
      { control_id: 'CIS-12', name: 'Network Infrastructure Management', description: 'Establish and maintain the secure configuration and management of network infrastructure.', family: 'Network Security', level: 'moderate' },
      { control_id: 'CIS-13', name: 'Network Monitoring and Defense', description: 'Operate processes and tooling to establish and maintain comprehensive network monitoring and defense.', family: 'Network Security', level: 'moderate' },
      { control_id: 'CIS-14', name: 'Security Awareness and Skills Training', description: 'Establish and maintain a security awareness program to influence behavior among the workforce to be security conscious.', family: 'Training', level: 'low' },
      { control_id: 'CIS-16', name: 'Application Software Security', description: 'Manage the security life cycle of in-house developed, hosted, or acquired software to prevent, detect, and remediate security weaknesses.', family: 'Application Security', level: 'moderate' },
    ],
  },

  // -------------------------------------------------------
  // PCI DSS v4.0
  // -------------------------------------------------------
  {
    name: 'PCI DSS',
    short_name: 'pci-dss',
    version: '4.0',
    description: 'Payment Card Industry Data Security Standard for organizations that handle branded credit cards.',
    controls: [
      { control_id: 'PCI-1', name: 'Install and Maintain Network Security Controls', description: 'Establish network security controls to protect cardholder data environments from unauthorized network traffic.', family: 'Network Security', level: 'high' },
      { control_id: 'PCI-2', name: 'Apply Secure Configurations to All System Components', description: 'Apply secure configuration standards to all system components to reduce vulnerabilities introduced by default settings.', family: 'System Configuration', level: 'high' },
      { control_id: 'PCI-3', name: 'Protect Stored Account Data', description: 'Protect stored account data using encryption, truncation, masking, and hashing as appropriate.', family: 'Data Protection', level: 'high' },
      { control_id: 'PCI-4', name: 'Protect Cardholder Data with Strong Cryptography During Transmission', description: 'Use strong cryptography to protect cardholder data during transmission over open, public networks.', family: 'Encryption', level: 'high' },
      { control_id: 'PCI-5', name: 'Protect All Systems and Networks from Malicious Software', description: 'Deploy anti-malware mechanisms on all systems commonly affected by malicious software.', family: 'Malware Protection', level: 'high' },
      { control_id: 'PCI-6', name: 'Develop and Maintain Secure Systems and Software', description: 'Develop and maintain secure systems and applications by applying security patches and following secure development practices.', family: 'Secure Development', level: 'high' },
      { control_id: 'PCI-7', name: 'Restrict Access to System Components and Cardholder Data by Business Need to Know', description: 'Restrict access to system components and cardholder data to only those individuals whose job requires such access.', family: 'Access Control', level: 'high' },
      { control_id: 'PCI-8', name: 'Identify Users and Authenticate Access to System Components', description: 'Assign a unique identification to each person with access and use strong authentication methods.', family: 'Identity and Authentication', level: 'high' },
      { control_id: 'PCI-9', name: 'Restrict Physical Access to Cardholder Data', description: 'Use appropriate facility entry controls to limit and monitor physical access to cardholder data.', family: 'Physical Security', level: 'high' },
      { control_id: 'PCI-10', name: 'Log and Monitor All Access to System Components and Cardholder Data', description: 'Implement logging mechanisms to track user activities and monitor all access to cardholder data environments.', family: 'Logging and Monitoring', level: 'high' },
      { control_id: 'PCI-11', name: 'Test Security of Systems and Networks Regularly', description: 'Regularly test security systems and processes including vulnerability scans and penetration testing.', family: 'Security Testing', level: 'high' },
      { control_id: 'PCI-12', name: 'Support Information Security with Organizational Policies and Programs', description: 'Maintain an information security policy that addresses all PCI DSS requirements for all personnel.', family: 'Governance', level: 'high' },
    ],
  },

  // -------------------------------------------------------
  // HIPAA Security Rule
  // -------------------------------------------------------
  {
    name: 'HIPAA Security Rule',
    short_name: 'hipaa',
    version: '2013',
    description: 'Administrative, physical, and technical safeguards to ensure the confidentiality, integrity, and availability of ePHI.',
    controls: [
      { control_id: 'HIPAA-164.308(a)(1)', name: 'Security Management Process', description: 'Implement policies and procedures to prevent, detect, contain, and correct security violations.', family: 'Administrative Safeguards', level: 'high' },
      { control_id: 'HIPAA-164.308(a)(3)', name: 'Workforce Security', description: 'Implement policies and procedures to ensure that workforce members have appropriate access to ePHI.', family: 'Administrative Safeguards', level: 'high' },
      { control_id: 'HIPAA-164.308(a)(4)', name: 'Information Access Management', description: 'Implement policies and procedures for authorizing access to ePHI consistent with applicable requirements.', family: 'Administrative Safeguards', level: 'high' },
      { control_id: 'HIPAA-164.308(a)(5)', name: 'Security Awareness and Training', description: 'Implement a security awareness and training program for all members of the workforce.', family: 'Administrative Safeguards', level: 'moderate' },
      { control_id: 'HIPAA-164.308(a)(6)', name: 'Security Incident Procedures', description: 'Implement policies and procedures to address security incidents.', family: 'Administrative Safeguards', level: 'high' },
      { control_id: 'HIPAA-164.308(a)(7)', name: 'Contingency Plan', description: 'Establish policies and procedures for responding to an emergency or other occurrence that damages systems containing ePHI.', family: 'Administrative Safeguards', level: 'high' },
      { control_id: 'HIPAA-164.310(a)(1)', name: 'Facility Access Controls', description: 'Implement policies and procedures to limit physical access to electronic information systems and the facilities in which they are housed.', family: 'Physical Safeguards', level: 'moderate' },
      { control_id: 'HIPAA-164.312(a)(1)', name: 'Access Control', description: 'Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons or programs.', family: 'Technical Safeguards', level: 'high' },
      { control_id: 'HIPAA-164.312(c)(1)', name: 'Integrity Controls', description: 'Implement policies and procedures to protect ePHI from improper alteration or destruction.', family: 'Technical Safeguards', level: 'high' },
      { control_id: 'HIPAA-164.312(e)(1)', name: 'Transmission Security', description: 'Implement technical security measures to guard against unauthorized access to ePHI being transmitted over an electronic network.', family: 'Technical Safeguards', level: 'high' },
    ],
  },
];

// --- Exported service functions ---

/**
 * Seed all built-in frameworks and their controls into the database.
 * Uses upsert logic so it can be called multiple times safely.
 */
export async function seedFrameworks(db: D1Database): Promise<{ frameworks: number; controls: number }> {
  let totalControls = 0;

  for (const fw of FRAMEWORKS) {
    // Upsert framework
    const existing = await db.prepare('SELECT id FROM compliance_frameworks WHERE short_name = ?').bind(fw.short_name).first();

    let frameworkId: string;
    if (existing) {
      frameworkId = existing.id as string;
    } else {
      frameworkId = crypto.randomUUID();
      await db.prepare(`
        INSERT INTO compliance_frameworks (id, name, short_name, version, description, controls_count)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(frameworkId, fw.name, fw.short_name, fw.version, fw.description, fw.controls.length).run();
    }

    // Insert controls (skip duplicates)
    for (const ctrl of fw.controls) {
      const ctrlExists = await db.prepare(
        'SELECT id FROM compliance_controls WHERE framework_id = ? AND control_id = ?'
      ).bind(frameworkId, ctrl.control_id).first();

      if (!ctrlExists) {
        await db.prepare(`
          INSERT INTO compliance_controls (id, framework_id, control_id, control_name, description, family, level)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(crypto.randomUUID(), frameworkId, ctrl.control_id, ctrl.name, ctrl.description, ctrl.family, ctrl.level || 'moderate').run();
        totalControls++;
      }
    }

    // Update controls count
    const count = await db.prepare('SELECT COUNT(*) as cnt FROM compliance_controls WHERE framework_id = ?').bind(frameworkId).first<{ cnt: number }>();
    await db.prepare('UPDATE compliance_frameworks SET controls_count = ?, updated_at = datetime(\'now\') WHERE id = ?').bind(count?.cnt || 0, frameworkId).run();
  }

  return { frameworks: FRAMEWORKS.length, controls: totalControls };
}

/**
 * Get compliance status summary for a single framework.
 * Returns counts of compliant / non-compliant / partial / not-assessed controls
 * along with an overall compliance percentage.
 */
export async function getFrameworkCompliance(db: D1Database, frameworkId: string): Promise<{
  total_controls: number;
  compliant: number;
  non_compliant: number;
  partial: number;
  not_assessed: number;
  compliance_percentage: number;
}> {
  const totalResult = await db.prepare(
    'SELECT COUNT(*) as total FROM compliance_controls WHERE framework_id = ?'
  ).bind(frameworkId).first<{ total: number }>();
  const total = totalResult?.total || 0;

  const mappingStats = await db.prepare(`
    SELECT
      SUM(CASE WHEN status = 'compliant' THEN 1 ELSE 0 END) as compliant,
      SUM(CASE WHEN status = 'non_compliant' THEN 1 ELSE 0 END) as non_compliant,
      SUM(CASE WHEN status = 'partial' THEN 1 ELSE 0 END) as partial,
      COUNT(DISTINCT control_id) as assessed
    FROM compliance_mappings WHERE framework_id = ?
  `).bind(frameworkId).first<{ compliant: number; non_compliant: number; partial: number; assessed: number }>();

  const compliant = mappingStats?.compliant || 0;
  const non_compliant = mappingStats?.non_compliant || 0;
  const partial = mappingStats?.partial || 0;
  const assessed = mappingStats?.assessed || 0;

  return {
    total_controls: total,
    compliant,
    non_compliant,
    partial,
    not_assessed: total - assessed,
    compliance_percentage: total > 0 ? Math.round((compliant / total) * 100) : 0,
  };
}

/**
 * Get gap analysis - every control in a framework with its current compliance
 * status and counts of linked findings and vulnerabilities.
 */
export async function getGapAnalysis(db: D1Database, frameworkId: string): Promise<any[]> {
  const result = await db.prepare(`
    SELECT cc.control_id, cc.control_name, cc.family, cc.description,
           COALESCE(cm.status, 'not_assessed') as compliance_status,
           COUNT(DISTINCT cm.finding_id) as linked_findings,
           COUNT(DISTINCT cm.vulnerability_id) as linked_vulns
    FROM compliance_controls cc
    LEFT JOIN compliance_mappings cm ON cc.framework_id = cm.framework_id AND cc.control_id = cm.control_id
    WHERE cc.framework_id = ?
    GROUP BY cc.control_id
    ORDER BY cc.family, cc.control_id
  `).bind(frameworkId).all();

  return result.results || [];
}

/**
 * List all active compliance frameworks with their compliance summaries.
 */
export async function listFrameworks(db: D1Database): Promise<any[]> {
  const frameworks = await db.prepare(
    'SELECT * FROM compliance_frameworks WHERE is_active = 1 ORDER BY name'
  ).all();

  const results = [];
  for (const fw of frameworks.results || []) {
    const compliance = await getFrameworkCompliance(db, fw.id as string);
    results.push({ ...fw, ...compliance });
  }

  return results;
}

/**
 * Create or update a compliance mapping linking a finding or vulnerability
 * to a specific framework control.
 */
export async function upsertMapping(db: D1Database, mapping: {
  finding_id?: string;
  vulnerability_id?: string;
  framework_id: string;
  control_id: string;
  status: string;
  evidence?: string;
  assessed_by?: string;
}): Promise<string> {
  const id = crypto.randomUUID();

  await db.prepare(`
    INSERT INTO compliance_mappings (id, finding_id, vulnerability_id, framework_id, control_id, status, evidence, assessed_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT DO NOTHING
  `).bind(
    id,
    mapping.finding_id || null,
    mapping.vulnerability_id || null,
    mapping.framework_id,
    mapping.control_id,
    mapping.status,
    mapping.evidence || null,
    mapping.assessed_by || null,
  ).run();

  return id;
}
