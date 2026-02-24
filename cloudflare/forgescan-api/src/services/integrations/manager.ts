import { sendEmail, testEmailConfig, type EmailConfig, type EmailMessage } from './email';
import { sendWebhook, testWebhookConfig, type WebhookConfig, type WebhookPayload } from './webhook';

export interface Integration {
  id: string;
  name: string;
  type: string;
  provider: string;
  config: string;
  is_active: number;
  last_tested_at: string | null;
  last_used_at: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface DispatchResult {
  success: boolean;
  status_code: number;
  response_body: string;
  error?: string;
  duration_ms: number;
}

// Dispatch an event to a specific integration
export async function dispatchToIntegration(
  db: D1Database,
  integration: Integration,
  eventType: string,
  data: Record<string, unknown>,
  sendgridApiKey?: string
): Promise<DispatchResult> {
  const config = JSON.parse(integration.config);
  let result: DispatchResult;

  if (integration.type === 'email') {
    const emailConfig: EmailConfig = {
      from_address: config.from_address || 'alerts@forgescan.com',
      from_name: config.from_name || 'ForgeScan',
      to_addresses: config.to_addresses || [],
      api_key: sendgridApiKey || config.api_key || '',
    };

    // Build email from event data
    const subject = `[ForgeScan] ${eventType}: ${data.title || data.message || 'Alert'}`;
    const textBody = buildTextEmail(eventType, data);
    const htmlBody = buildHtmlEmail(eventType, data);

    result = await sendEmail(emailConfig, { subject, text_body: textBody, html_body: htmlBody });
  } else if (integration.type === 'webhook') {
    const webhookConfig: WebhookConfig = {
      url: config.url,
      secret: config.secret,
      headers: config.headers,
    };

    result = await sendWebhook(webhookConfig, {
      event_type: eventType,
      timestamp: new Date().toISOString(),
      data,
    });
  } else {
    result = {
      success: false,
      status_code: 0,
      response_body: '',
      error: `Unknown integration type: ${integration.type}`,
      duration_ms: 0,
    };
  }

  // Log the dispatch
  await db.prepare(`
    INSERT INTO integration_logs (id, integration_id, event_type, status, request_payload, response_code, response_body, error_message, duration_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    crypto.randomUUID(),
    integration.id,
    eventType,
    result.success ? 'success' : 'failed',
    JSON.stringify(data).substring(0, 1000),
    result.status_code,
    result.response_body?.substring(0, 500) || null,
    result.error || null,
    result.duration_ms,
  ).run();

  // Update last_used_at
  await db.prepare(
    "UPDATE integrations SET last_used_at = datetime('now'), updated_at = datetime('now') WHERE id = ?"
  ).bind(integration.id).run();

  return result;
}

// Test an integration
export async function testIntegration(
  db: D1Database,
  integration: Integration,
  sendgridApiKey?: string
): Promise<DispatchResult> {
  const config = JSON.parse(integration.config);
  let result: DispatchResult;

  if (integration.type === 'email') {
    const emailConfig: EmailConfig = {
      from_address: config.from_address || 'alerts@forgescan.com',
      from_name: config.from_name || 'ForgeScan',
      to_addresses: config.to_addresses || [],
      api_key: sendgridApiKey || config.api_key || '',
    };
    result = await testEmailConfig(emailConfig);
  } else if (integration.type === 'webhook') {
    const webhookConfig: WebhookConfig = {
      url: config.url,
      secret: config.secret,
      headers: config.headers,
    };
    result = await testWebhookConfig(webhookConfig);
  } else {
    result = {
      success: false,
      status_code: 0,
      response_body: '',
      error: `Unknown integration type: ${integration.type}`,
      duration_ms: 0,
    };
  }

  // Log the test
  await db.prepare(`
    INSERT INTO integration_logs (id, integration_id, event_type, status, response_code, response_body, error_message, duration_ms)
    VALUES (?, ?, 'test', ?, ?, ?, ?, ?)
  `).bind(
    crypto.randomUUID(),
    integration.id,
    result.success ? 'success' : 'failed',
    result.status_code,
    result.response_body?.substring(0, 500) || null,
    result.error || null,
    result.duration_ms,
  ).run();

  // Update last_tested_at
  await db.prepare(
    "UPDATE integrations SET last_tested_at = datetime('now'), updated_at = datetime('now') WHERE id = ?"
  ).bind(integration.id).run();

  return result;
}

// Dispatch an event to ALL active integrations
export async function dispatchEvent(
  db: D1Database,
  eventType: string,
  data: Record<string, unknown>,
  sendgridApiKey?: string
): Promise<{ sent: number; failed: number }> {
  const integrations = await db.prepare(
    'SELECT * FROM integrations WHERE is_active = 1'
  ).all<Integration>();

  let sent = 0;
  let failed = 0;

  for (const integration of integrations.results || []) {
    const result = await dispatchToIntegration(db, integration, eventType, data, sendgridApiKey);
    if (result.success) sent++;
    else failed++;
  }

  return { sent, failed };
}

// Helper: Build plain text email from event data
function buildTextEmail(eventType: string, data: Record<string, unknown>): string {
  const lines = [
    `ForgeScan Alert`,
    `Event: ${eventType}`,
    `Time: ${new Date().toISOString()}`,
    `---`,
  ];

  if (data.title) lines.push(`Title: ${data.title}`);
  if (data.message) lines.push(`Message: ${data.message}`);
  if (data.severity) lines.push(`Severity: ${data.severity}`);
  if (data.scan_name) lines.push(`Scan: ${data.scan_name}`);
  if (data.findings_count !== undefined) lines.push(`Findings: ${data.findings_count}`);
  if (data.cve_id) lines.push(`CVE: ${data.cve_id}`);
  if (data.asset) lines.push(`Asset: ${data.asset}`);

  lines.push('', '---', 'ForgeScan - Enterprise Vulnerability Management');
  return lines.join('\n');
}

// Helper: Build HTML email from event data
function buildHtmlEmail(eventType: string, data: Record<string, unknown>): string {
  const severityColor = (s: string) => {
    switch (s) {
      case 'critical': return '#dc2626';
      case 'high': return '#ea580c';
      case 'medium': return '#d97706';
      case 'low': return '#2563eb';
      default: return '#6b7280';
    }
  };

  let details = '';
  if (data.title) details += `<tr><td style="padding:4px 8px;font-weight:bold;">Title</td><td style="padding:4px 8px;">${data.title}</td></tr>`;
  if (data.message) details += `<tr><td style="padding:4px 8px;font-weight:bold;">Message</td><td style="padding:4px 8px;">${data.message}</td></tr>`;
  if (data.severity) details += `<tr><td style="padding:4px 8px;font-weight:bold;">Severity</td><td style="padding:4px 8px;"><span style="background:${severityColor(String(data.severity))};color:white;padding:2px 8px;border-radius:4px;">${data.severity}</span></td></tr>`;
  if (data.scan_name) details += `<tr><td style="padding:4px 8px;font-weight:bold;">Scan</td><td style="padding:4px 8px;">${data.scan_name}</td></tr>`;
  if (data.findings_count !== undefined) details += `<tr><td style="padding:4px 8px;font-weight:bold;">Findings</td><td style="padding:4px 8px;">${data.findings_count}</td></tr>`;
  if (data.cve_id) details += `<tr><td style="padding:4px 8px;font-weight:bold;">CVE</td><td style="padding:4px 8px;">${data.cve_id}</td></tr>`;
  if (data.asset) details += `<tr><td style="padding:4px 8px;font-weight:bold;">Asset</td><td style="padding:4px 8px;">${data.asset}</td></tr>`;

  return `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
      <div style="background:#1e293b;color:white;padding:16px 24px;border-radius:8px 8px 0 0;">
        <h2 style="margin:0;">ForgeScan</h2>
        <p style="margin:4px 0 0;opacity:0.8;">${eventType}</p>
      </div>
      <div style="border:1px solid #e2e8f0;padding:24px;border-radius:0 0 8px 8px;">
        <table style="width:100%;border-collapse:collapse;">${details}</table>
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:16px 0;">
        <p style="color:#6b7280;font-size:12px;">Sent at ${new Date().toISOString()}</p>
      </div>
    </div>
  `;
}
