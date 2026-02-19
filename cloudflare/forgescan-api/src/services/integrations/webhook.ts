export interface WebhookConfig {
  url: string;
  secret?: string; // HMAC-SHA256 signing secret
  headers?: Record<string, string>; // Additional headers
}

export interface WebhookPayload {
  event_type: string;
  timestamp: string;
  data: Record<string, unknown>;
}

export interface WebhookResult {
  success: boolean;
  status_code: number;
  response_body: string;
  error?: string;
  duration_ms: number;
}

async function signPayload(payload: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function sendWebhook(
  config: WebhookConfig,
  payload: WebhookPayload
): Promise<WebhookResult> {
  const start = Date.now();

  try {
    const body = JSON.stringify(payload);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'ForgeScan-Webhook/1.0',
      'X-ForgeScan-Event': payload.event_type,
      'X-ForgeScan-Timestamp': payload.timestamp,
      ...(config.headers || {}),
    };

    // Add HMAC signature if secret is configured
    if (config.secret) {
      const signature = await signPayload(body, config.secret);
      headers['X-ForgeScan-Signature'] = `sha256=${signature}`;
    }

    const response = await fetch(config.url, {
      method: 'POST',
      headers,
      body,
    });

    const duration_ms = Date.now() - start;
    const responseBody = await response.text();

    return {
      success: response.status >= 200 && response.status < 300,
      status_code: response.status,
      response_body: responseBody.substring(0, 500),
      duration_ms,
    };
  } catch (error) {
    const duration_ms = Date.now() - start;
    return {
      success: false,
      status_code: 0,
      response_body: '',
      error: error instanceof Error ? error.message : 'Unknown error',
      duration_ms,
    };
  }
}

// Test the webhook configuration
export async function testWebhookConfig(config: WebhookConfig): Promise<WebhookResult> {
  return sendWebhook(config, {
    event_type: 'test',
    timestamp: new Date().toISOString(),
    data: {
      message: 'This is a test webhook from ForgeScan 360',
      source: 'integration_test',
    },
  });
}
