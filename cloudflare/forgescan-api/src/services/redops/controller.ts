// ─────────────────────────────────────────────────────────────────────────────
// ForgeRedOps Agent Controller — Campaign Orchestration Engine
// ─────────────────────────────────────────────────────────────────────────────
//
// Picks up launched campaigns, dispatches agents, collects findings,
// and publishes events to the Forge Event Bus.

import { publish } from '../event-bus';
import { createAIProvider, type ForgeAIProvider, type AISecurityFinding } from '../ai-provider';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface Campaign {
  id: string;
  name: string;
  status: string;
  campaign_type: string;
  target_scope: string;
  exclusions: string | null;
  agent_categories: string;
  max_concurrent_agents: number;
  exploitation_level: string;
  risk_threshold: string;
  auto_poam: number;
  compliance_mapping: number;
  total_agents: number;
  active_agents: number;
  completed_agents: number;
  failed_agents: number;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  exploitable_count: number;
}

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

interface AgentImplementation {
  execute(
    agent: Agent,
    campaign: Campaign,
    targets: Record<string, unknown>,
    aiProvider: ForgeAIProvider,
    db: D1Database,
    onFinding: (finding: AISecurityFinding, agent: Agent) => Promise<void>,
    onProgress: (agent: Agent, log: string) => Promise<void>
  ): Promise<{ success: boolean; error?: string }>;
}

// Agent implementation registry — agents register themselves here
const agentRegistry = new Map<string, AgentImplementation>();

export function registerAgent(agentType: string, impl: AgentImplementation): void {
  agentRegistry.set(agentType, impl);
}

// ─────────────────────────────────────────────────────────────────────────────
// Campaign Controller
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Execute a launched campaign: iterate through agents and run them.
 * Called from the campaign launch endpoint after agents are created.
 */
export async function executeCampaign(
  db: D1Database,
  campaignId: string,
  anthropicApiKey: string,
  sendgridApiKey?: string
): Promise<{ success: boolean; findings_total: number; error?: string }> {
  // Load the campaign
  const campaign = await db
    .prepare('SELECT * FROM redops_campaigns WHERE id = ?')
    .bind(campaignId)
    .first<Campaign>();

  if (!campaign) {
    return { success: false, findings_total: 0, error: 'Campaign not found' };
  }

  // Parse target scope
  const targets: Record<string, unknown> = typeof campaign.target_scope === 'string'
    ? JSON.parse(campaign.target_scope)
    : campaign.target_scope;

  // Create AI provider with per-campaign token budget
  const aiProvider = createAIProvider(anthropicApiKey, {
    token_budget: 200000, // 200K tokens per campaign
  });

  // Transition campaign to reconnaissance
  await updateCampaignStatus(db, campaignId, 'reconnaissance');
  await publish(db, 'forge.redops.campaign.launched', 'forgeredops', {
    campaign_id: campaignId,
    campaign_name: campaign.name,
    total_agents: campaign.total_agents,
    exploitation_level: campaign.exploitation_level,
  }, { correlation_id: campaignId, sendgridApiKey });

  // Load queued agents
  const agents = await db
    .prepare(
      "SELECT * FROM redops_agents WHERE campaign_id = ? AND status = 'queued' ORDER BY created_at ASC"
    )
    .bind(campaignId)
    .all<Agent>();

  let totalFindings = 0;
  let completedCount = 0;
  let failedCount = 0;

  // Process agents (respecting max_concurrent_agents via batching)
  const agentList = agents.results || [];
  const batchSize = campaign.max_concurrent_agents;

  for (let i = 0; i < agentList.length; i += batchSize) {
    const batch = agentList.slice(i, i + batchSize);

    // Check if campaign was cancelled mid-execution
    const currentStatus = await db
      .prepare('SELECT status FROM redops_campaigns WHERE id = ?')
      .bind(campaignId)
      .first<{ status: string }>();

    if (currentStatus?.status === 'cancelled') {
      break;
    }

    // Transition to scanning/exploitation based on progress
    if (completedCount === 0) {
      await updateCampaignStatus(db, campaignId, 'scanning');
    }

    // Execute batch concurrently
    const batchResults = await Promise.allSettled(
      batch.map((agent) =>
        executeAgent(db, agent, campaign, targets, aiProvider, sendgridApiKey)
      )
    );

    for (const result of batchResults) {
      if (result.status === 'fulfilled') {
        totalFindings += result.value.findings_count;
        if (result.value.success) completedCount++;
        else failedCount++;
      } else {
        failedCount++;
      }
    }

    // Update campaign progress
    await db
      .prepare(
        `UPDATE redops_campaigns SET
          active_agents = 0,
          completed_agents = ?,
          failed_agents = ?,
          updated_at = datetime('now')
        WHERE id = ?`
      )
      .bind(completedCount, failedCount, campaignId)
      .run();
  }

  // Finalize campaign
  await finalizeCampaign(db, campaignId, sendgridApiKey);

  return { success: true, findings_total: totalFindings };
}

/**
 * Execute a single agent within a campaign.
 */
async function executeAgent(
  db: D1Database,
  agent: Agent,
  campaign: Campaign,
  targets: Record<string, unknown>,
  aiProvider: ForgeAIProvider,
  sendgridApiKey?: string
): Promise<{ success: boolean; findings_count: number }> {
  let findingsCount = 0;

  // Update agent status to initializing
  await updateAgentStatus(db, agent.id, 'initializing');
  await appendAgentLog(db, agent.id, `Agent ${agent.agent_type} initializing`);

  try {
    // Check if we have an implementation for this agent type
    const impl = agentRegistry.get(agent.agent_type);

    if (!impl) {
      // No implementation yet — mark as completed with 0 findings
      await appendAgentLog(db, agent.id, `No implementation registered for ${agent.agent_type} — skipping`);
      await updateAgentStatus(db, agent.id, 'completed');
      await db
        .prepare(
          "UPDATE redops_agents SET tests_planned = 0, tests_completed = 0, completed_at = datetime('now'), updated_at = datetime('now') WHERE id = ?"
        )
        .bind(agent.id)
        .run();
      return { success: true, findings_count: 0 };
    }

    // Assign target from scope
    const agentTarget = resolveTarget(targets, agent.agent_category);
    await db
      .prepare('UPDATE redops_agents SET target = ?, updated_at = datetime(\'now\') WHERE id = ?')
      .bind(agentTarget, agent.id)
      .run();
    agent.target = agentTarget;

    // Transition to testing
    await updateAgentStatus(db, agent.id, 'testing');
    await appendAgentLog(db, agent.id, `Testing target: ${agentTarget}`);

    // Update campaign active count
    await db
      .prepare(
        'UPDATE redops_campaigns SET active_agents = active_agents + 1, updated_at = datetime(\'now\') WHERE id = ?'
      )
      .bind(campaign.id)
      .run();

    // Run the agent implementation
    const result = await impl.execute(
      agent,
      campaign,
      targets,
      aiProvider,
      db,
      // onFinding callback
      async (finding: AISecurityFinding, agentRef: Agent) => {
        findingsCount++;
        await persistFinding(db, finding, agentRef, campaign);

        // Publish event for the finding
        await publish(db, 'forge.redops.finding.discovered', 'forgeredops', {
          campaign_id: campaign.id,
          agent_id: agentRef.id,
          agent_type: agentRef.agent_type,
          title: finding.title,
          severity: finding.severity,
          exploitable: finding.exploitable,
          cwe_id: finding.cwe_id,
          cve_id: finding.cve_id,
          target: agentRef.target,
        }, { correlation_id: campaign.id, sendgridApiKey });

        // Exploitation success event
        if (finding.exploitable) {
          await publish(db, 'forge.redops.exploitation.success', 'forgeredops', {
            campaign_id: campaign.id,
            agent_id: agentRef.id,
            title: finding.title,
            severity: finding.severity,
            exploitation_proof: finding.exploitation_proof,
            target: agentRef.target,
            cwe_id: finding.cwe_id,
          }, { correlation_id: campaign.id, sendgridApiKey });
        }
      },
      // onProgress callback
      async (agentRef: Agent, log: string) => {
        await appendAgentLog(db, agentRef.id, log);
      }
    );

    if (result.success) {
      await updateAgentStatus(db, agent.id, 'completed');
      await appendAgentLog(db, agent.id, `Agent completed with ${findingsCount} findings`);
    } else {
      await updateAgentStatus(db, agent.id, 'failed');
      await appendAgentLog(db, agent.id, `Agent failed: ${result.error}`);
      await db
        .prepare('UPDATE redops_agents SET error_message = ?, updated_at = datetime(\'now\') WHERE id = ?')
        .bind(result.error || 'Unknown error', agent.id)
        .run();
    }

    // Update agent stats
    await db
      .prepare(
        `UPDATE redops_agents SET
          findings_count = ?,
          exploitable_count = (SELECT COUNT(*) FROM redops_findings WHERE agent_id = ? AND exploitable = 1),
          completed_at = datetime('now'),
          duration_seconds = CAST((julianday('now') - julianday(started_at)) * 86400 AS INTEGER),
          updated_at = datetime('now')
        WHERE id = ?`
      )
      .bind(findingsCount, agent.id, agent.id)
      .run();

    // Decrement active count
    await db
      .prepare(
        'UPDATE redops_campaigns SET active_agents = MAX(0, active_agents - 1), updated_at = datetime(\'now\') WHERE id = ?'
      )
      .bind(campaign.id)
      .run();

    return { success: result.success, findings_count: findingsCount };
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : 'Unexpected error';
    await updateAgentStatus(db, agent.id, 'failed');
    await appendAgentLog(db, agent.id, `Agent error: ${errorMsg}`);
    await db
      .prepare('UPDATE redops_agents SET error_message = ?, updated_at = datetime(\'now\') WHERE id = ?')
      .bind(errorMsg, agent.id)
      .run();

    return { success: false, findings_count: findingsCount };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Persist an AI-generated finding to the redops_findings table */
async function persistFinding(
  db: D1Database,
  finding: AISecurityFinding,
  agent: Agent,
  campaign: Campaign
): Promise<string> {
  const findingId = crypto.randomUUID();

  await db
    .prepare(
      `INSERT INTO redops_findings (
        id, campaign_id, agent_id, title, description, severity,
        attack_vector, attack_category, cwe_id, cve_id, cvss_score,
        exploitable, exploitation_proof, exploitation_steps,
        mitre_tactic, mitre_technique, remediation, remediation_effort,
        nist_controls, status, request_data, response_data,
        discovered_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, datetime('now'), datetime('now'), datetime('now'))`
    )
    .bind(
      findingId,
      campaign.id,
      agent.id,
      finding.title,
      finding.description || null,
      finding.severity,
      finding.attack_vector || null,
      finding.attack_category || null,
      finding.cwe_id || null,
      finding.cve_id || null,
      finding.cvss_score || null,
      finding.exploitable ? 1 : 0,
      finding.exploitation_proof || null,
      finding.exploitation_steps ? JSON.stringify(finding.exploitation_steps) : null,
      finding.mitre_tactic || null,
      finding.mitre_technique || null,
      finding.remediation || null,
      finding.remediation_effort || null,
      finding.nist_controls ? JSON.stringify(finding.nist_controls) : null,
      finding.evidence?.request || null,
      finding.evidence?.response || null
    )
    .run();

  // Update campaign severity counts
  const severityCol = `${finding.severity}_count`;
  const validCols = ['critical_count', 'high_count', 'medium_count', 'low_count', 'info_count'];
  if (validCols.includes(severityCol)) {
    await db
      .prepare(
        `UPDATE redops_campaigns SET
          findings_count = findings_count + 1,
          ${severityCol} = ${severityCol} + 1,
          exploitable_count = exploitable_count + ${finding.exploitable ? 1 : 0},
          updated_at = datetime('now')
        WHERE id = ?`
      )
      .bind(campaign.id)
      .run();
  }

  return findingId;
}

/** Finalize a campaign: compute duration, update status, publish completion event */
async function finalizeCampaign(
  db: D1Database,
  campaignId: string,
  sendgridApiKey?: string
): Promise<void> {
  const campaign = await db
    .prepare('SELECT * FROM redops_campaigns WHERE id = ?')
    .bind(campaignId)
    .first<Campaign>();

  if (!campaign) return;

  // Only finalize if not already cancelled
  if (campaign.status === 'cancelled') return;

  const finalStatus = campaign.failed_agents > 0 && campaign.completed_agents === 0 ? 'failed' : 'completed';

  await db
    .prepare(
      `UPDATE redops_campaigns SET
        status = ?,
        completed_at = datetime('now'),
        duration_seconds = CAST((julianday('now') - julianday(started_at)) * 86400 AS INTEGER),
        updated_at = datetime('now')
      WHERE id = ?`
    )
    .bind(finalStatus, campaignId)
    .run();

  await publish(db, 'forge.redops.campaign.completed', 'forgeredops', {
    campaign_id: campaignId,
    campaign_name: campaign.name,
    status: finalStatus,
    findings_count: campaign.findings_count,
    critical_count: campaign.critical_count,
    high_count: campaign.high_count,
    exploitable_count: campaign.exploitable_count,
    completed_agents: campaign.completed_agents,
    failed_agents: campaign.failed_agents,
  }, { correlation_id: campaignId, sendgridApiKey });
}

/** Update agent status */
async function updateAgentStatus(db: D1Database, agentId: string, status: string): Promise<void> {
  const extra = status === 'testing' ? ", started_at = datetime('now')" : '';
  await db
    .prepare(
      `UPDATE redops_agents SET status = ?${extra}, last_activity = datetime('now'), updated_at = datetime('now') WHERE id = ?`
    )
    .bind(status, agentId)
    .run();
}

/** Update campaign status */
async function updateCampaignStatus(db: D1Database, campaignId: string, status: string): Promise<void> {
  await db
    .prepare("UPDATE redops_campaigns SET status = ?, updated_at = datetime('now') WHERE id = ?")
    .bind(status, campaignId)
    .run();
}

/** Append a log entry to an agent's execution log */
async function appendAgentLog(db: D1Database, agentId: string, message: string): Promise<void> {
  const agent = await db
    .prepare('SELECT execution_log FROM redops_agents WHERE id = ?')
    .bind(agentId)
    .first<{ execution_log: string | null }>();

  const log: Array<{ timestamp: string; message: string }> = agent?.execution_log
    ? JSON.parse(agent.execution_log)
    : [];

  log.push({ timestamp: new Date().toISOString(), message });

  // Keep only last 100 entries
  const trimmed = log.slice(-100);

  await db
    .prepare("UPDATE redops_agents SET execution_log = ?, updated_at = datetime('now') WHERE id = ?")
    .bind(JSON.stringify(trimmed), agentId)
    .run();
}

/** Resolve a target for an agent based on the campaign scope and agent category */
function resolveTarget(targets: Record<string, unknown>, agentCategory: string): string {
  // For web/API agents, prefer URLs; for network agents, prefer hosts
  if ((agentCategory === 'web' || agentCategory === 'api') && targets.urls) {
    const urls = targets.urls as string[];
    if (urls.length > 0) return urls[0];
  }

  if (targets.hosts) {
    const hosts = targets.hosts as string[];
    if (hosts.length > 0) return hosts[0];
  }

  if (targets.networks) {
    const networks = targets.networks as string[];
    if (networks.length > 0) return networks[0];
  }

  if (targets.domains) {
    const domains = targets.domains as string[];
    if (domains.length > 0) return domains[0];
  }

  return 'unknown';
}
