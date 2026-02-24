export interface EmailConfig {
  from_address: string;
  from_name?: string;
  to_addresses: string[];
  api_key: string; // SendGrid API key
}

export interface EmailMessage {
  subject: string;
  text_body: string;
  html_body?: string;
}

export interface EmailResult {
  success: boolean;
  status_code: number;
  response_body: string;
  error?: string;
  duration_ms: number;
}

export async function sendEmail(
  config: EmailConfig,
  message: EmailMessage
): Promise<EmailResult> {
  const start = Date.now();

  try {
    const payload = {
      personalizations: [{
        to: config.to_addresses.map(email => ({ email })),
      }],
      from: {
        email: config.from_address,
        name: config.from_name || 'ForgeScan',
      },
      subject: message.subject,
      content: [
        { type: 'text/plain', value: message.text_body },
        ...(message.html_body ? [{ type: 'text/html', value: message.html_body }] : []),
      ],
    };

    const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.api_key}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
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

// Test the email configuration by sending a test message
export async function testEmailConfig(config: EmailConfig): Promise<EmailResult> {
  return sendEmail(config, {
    subject: 'ForgeScan - Integration Test',
    text_body: 'This is a test email from ForgeScan. If you received this, your email integration is configured correctly.',
    html_body: '<h2>ForgeScan - Integration Test</h2><p>This is a test email from ForgeScan.</p><p>If you received this, your email integration is configured correctly.</p><hr><p style="color: #666; font-size: 12px;">Sent at: ' + new Date().toISOString() + '</p>',
  });
}
