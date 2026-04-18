/**
 * @fileoverview Arniko Security Alert Service
 * Multi-channel alerting system for security events. Supports Slack, PagerDuty, and Email notifications.
 * @module arniko/alert-service
 */

/** Severity levels supported by the alerting system */
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Configuration options for alert channels */
interface AlertServiceConfig {
  /** Slack incoming webhook configuration */
  slack?: {
    /** Slack incoming webhook URL (e.g., https://hooks.slack.com/services/...) */
    webhookUrl: string;
  };
  /** PagerDuty Events API v2 configuration */
  pagerduty?: {
    /** PagerDuty integration/routing key */
    integrationKey: string;
  };
  /** Email notification configuration */
  email?: {
    /** Array of recipient email addresses */
    to: string[];
    /** Sender email address (must be verified in Resend) */
    from?: string;
  };
  /** Resend API configuration */
  resend?: {
    /** Resend API key */
    apiKey: string;
    /** Sender email address (must be verified in Resend) */
    from: string;
  };
}

/** Security event payload for alerting */
interface SecurityEvent {
  /** Event classification (e.g., 'unauthorized_access', 'data_exfiltration') */
  type: string;
  /** Severity level of the event */
  severity: string;
  /** Short summary of the event */
  title: string;
  /** Detailed description of what occurred */
  description: string;
  /** ID of the user associated with the event (victim or perpetrator) */
  userId: string;
  /** Additional contextual data (IP addresses, user agents, etc.) */
  metadata?: Record<string, unknown>;
}

/** Resend API response type */
interface ResendSendResponse {
  id?: string;
  error?: { message: string };
}

/**
 * Environment configuration for Resend integration.
 * Configure via environment variables:
 * - RESEND_API_KEY: Your Resend API key
 * - RESEND_FROM_EMAIL: Verified sender email address (default: security@arniko.io)
 * - SECURITY_ALERT_EMAILS: Comma-separated list of recipient emails
 */
interface ResendConfig {
  apiKey: string | undefined;
  fromEmail: string;
  toEmails: string[];
}

/**
 * Loads Resend configuration from environment variables.
 * @returns {ResendConfig} Configuration object for Resend
 */
function getResendConfig(): ResendConfig {
  return {
    apiKey: process.env.RESEND_API_KEY,
    fromEmail: process.env.RESEND_FROM_EMAIL || 'security@arniko.io',
    toEmails: process.env.SECURITY_ALERT_EMAILS?.split(',').map(e => e.trim()) || [],
  };
}

/**
 * Sends a security alert email using Resend API.
 * Falls back to console logging if Resend is not configured.
 * 
 * @param {SecurityEvent} event - The security event to send an alert for
 * @param {string[]} [recipients] - Optional override recipients (defaults to env SECURITY_ALERT_EMAILS)
 * @param {string} [fromEmail] - Optional sender email (defaults to env RESEND_FROM_EMAIL)
 * @returns {Promise<{ success: boolean; messageId?: string; error?: string }>} Result of the email send attempt
 * 
 * @example
 * ```typescript
 * await sendSecurityAlert({
 *   type: 'unauthorized_access',
 *   severity: 'critical',
 *   title: 'Unauthorized database access detected',
 *   description: 'Multiple failed authentication attempts...',
 *   userId: 'user_12345',
 *   metadata: { ip: '192.168.1.1', attempts: 5 }
 * });
 * ```
 */
export async function sendSecurityAlert(
  event: SecurityEvent,
  recipients?: string[],
  fromEmail?: string
): Promise<{ success: boolean; messageId?: string; error?: string }> {
  const config = getResendConfig();
  const to = recipients || config.toEmails;
  const from = fromEmail || config.fromEmail;

  // Build email content
  const subject = `[${event.severity.toUpperCase()}] Arniko Security Alert: ${event.title}`;
  const htmlBody = buildSecurityAlertHtml(event);
  const textBody = buildSecurityAlertText(event);

  // Check if Resend is configured
  if (!config.apiKey) {
    console.warn('[sendSecurityAlert] RESEND_API_KEY not configured. Falling back to console logging.');
    console.log('[sendSecurityAlert] Email Alert (console fallback):');
    console.log(`  From: ${from}`);
    console.log(`  To: ${to.join(', ') || 'no recipients configured'}`);
    console.log(`  Subject: ${subject}`);
    console.log(`  Body Preview:\n${textBody.substring(0, 500)}...`);
    return { success: true, messageId: 'console-fallback' };
  }

  if (to.length === 0) {
    const error = 'No recipients configured. Set SECURITY_ALERT_EMAILS environment variable.';
    console.error(`[sendSecurityAlert] ${error}`);
    return { success: false, error };
  }

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from,
        to,
        subject,
        html: htmlBody,
        text: textBody,
        tags: [
          { name: 'source', value: 'arniko-security' },
          { name: 'severity', value: event.severity.toLowerCase() },
          { name: 'event_type', value: event.type },
        ],
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ error: { message: 'Unknown error' } })) as ResendSendResponse;
      const errorMessage = errorData.error?.message || `HTTP ${response.status}: ${response.statusText}`;
      throw new Error(errorMessage);
    }

    const data = await response.json() as ResendSendResponse;
    console.log(`[sendSecurityAlert] Email sent successfully. Message ID: ${data.id}`);
    return { success: true, messageId: data.id };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error(`[sendSecurityAlert] Failed to send email:`, errorMessage);
    return { success: false, error: errorMessage };
  }
}

/**
 * Builds HTML email body for security alerts.
 * @private
 * @param {SecurityEvent} event - Security event data
 * @returns {string} HTML formatted email body
 */
function buildSecurityAlertHtml(event: SecurityEvent): string {
  const severityColor = getSeverityColor(event.severity);
  const metadataHtml = event.metadata 
    ? `<pre style="background: #f5f5f5; padding: 12px; border-radius: 4px; overflow-x: auto;">${JSON.stringify(event.metadata, null, 2)}</pre>`
    : '<p><em>No metadata available</em></p>';

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Arniko Security Alert</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: ${severityColor}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
    .header h1 { margin: 0; font-size: 20px; }
    .content { background: #fff; border: 1px solid #e0e0e0; border-top: none; padding: 20px; border-radius: 0 0 8px 8px; }
    .field { margin-bottom: 12px; }
    .label { font-weight: 600; color: #666; font-size: 12px; text-transform: uppercase; }
    .value { font-size: 14px; }
    .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; }
    .badge { display: inline-block; padding: 4px 8px; background: ${severityColor}; color: white; border-radius: 4px; font-size: 12px; font-weight: 600; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🚨 ${escapeHtml(event.title)}</h1>
  </div>
  <div class="content">
    <div class="field">
      <div class="label">Severity</div>
      <div class="value"><span class="badge">${event.severity.toUpperCase()}</span></div>
    </div>
    <div class="field">
      <div class="label">Event Type</div>
      <div class="value">${escapeHtml(event.type)}</div>
    </div>
    <div class="field">
      <div class="label">User ID</div>
      <div class="value">${escapeHtml(event.userId)}</div>
    </div>
    <div class="field">
      <div class="label">Timestamp</div>
      <div class="value">${new Date().toISOString()}</div>
    </div>
    <div class="field">
      <div class="label">Description</div>
      <div class="value">${escapeHtml(event.description).replace(/\n/g, '<br>')}</div>
    </div>
    <div class="field">
      <div class="label">Metadata</div>
      ${metadataHtml}
    </div>
    <div class="footer">
      This is an automated security alert from Arniko.<br>
      Event ID: ${escapeHtml(event.type)}-${Date.now()}
    </div>
  </div>
</body>
</html>
  `.trim();
}

/**
 * Builds plain text email body for security alerts.
 * @private
 * @param {SecurityEvent} event - Security event data
 * @returns {string} Plain text formatted email body
 */
function buildSecurityAlertText(event: SecurityEvent): string {
  const metadata = event.metadata 
    ? JSON.stringify(event.metadata, null, 2)
    : 'None';

  return `
SECURITY ALERT - Arniko
=======================

Title:       ${event.title}
Severity:    ${event.severity.toUpperCase()}
Type:        ${event.type}
User ID:     ${event.userId}
Timestamp:   ${new Date().toISOString()}

DESCRIPTION
-----------
${event.description}

METADATA
--------
${metadata}

---
This is an automated security alert from Arniko.
Event ID: ${event.type}-${Date.now()}
  `.trim();
}

/**
 * Gets color code for severity level.
 * @private
 * @param {string} severity - Severity level
 * @returns {string} Hex color code
 */
function getSeverityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return '#dc3545'; // Red
    case 'high':
      return '#fd7e14'; // Orange
    case 'medium':
      return '#ffc107'; // Yellow
    case 'low':
      return '#28a745'; // Green
    default:
      return '#6c757d'; // Gray
  }
}

/**
 * Escapes HTML special characters to prevent XSS.
 * @private
 * @param {string} text - Text to escape
 * @returns {string} Escaped HTML
 */
function escapeHtml(text: string): string {
  const div = typeof document !== 'undefined' ? document.createElement('div') : null;
  if (div) {
    div.textContent = text;
    return div.innerHTML;
  }
  // Server-side fallback
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Service for dispatching security alerts across multiple notification channels.
 * Implements graceful degradation - failures in one channel do not affect others.
 */
export class AlertService {
  private readonly config: AlertServiceConfig;

  /**
   * Creates an instance of AlertService.
   * @param {AlertServiceConfig} config - Configuration for enabled notification channels
   */
  constructor(config: AlertServiceConfig) {
    this.config = config;
  }

  /**
   * Dispatches a security alert to all configured channels concurrently.
   * Errors in individual channels are logged but do not throw or block other channels.
   * 
   * @param {SecurityEvent} event - The security event to alert on
   * @returns {Promise<void>} Resolves when all channel attempts complete
   */
  async sendAlert(event: SecurityEvent): Promise<void> {
    const promises: Promise<void>[] = [];

    if (this.config.slack) {
      promises.push(this.sendSlack(this.config.slack.webhookUrl, event));
    }

    if (this.config.pagerduty) {
      promises.push(this.sendPagerDuty(this.config.pagerduty.integrationKey, event));
    }

    // Use Resend if configured, otherwise fall back to legacy email config
    if (this.config.resend) {
      promises.push(this.sendEmailViaResend(event));
    } else if (this.config.email) {
      promises.push(this.sendEmailLegacy(this.config.email.to, event, this.config.email.from));
    }

    // Wait for all channels to complete, regardless of individual failures
    await Promise.allSettled(promises);
  }

  /**
   * Maps severity strings to Slack attachment colors.
   * @private
   * @param {string} severity - Event severity level
   * @returns {string} Slack color code (danger, warning, hex color, or default)
   */
  private getSlackColor(severity: string): string {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'danger'; // Red
      case 'high':
        return 'warning'; // Yellow/Orange
      case 'medium':
        return '#439FE0'; // Blue
      case 'low':
        return 'good'; // Green
      default:
        return '#808080'; // Grey for unknown/info
    }
  }

  /**
   * Sends formatted alert to Slack via incoming webhook.
   * @private
   * @param {string} webhookUrl - Slack incoming webhook URL
   * @param {SecurityEvent} event - Security event data
   * @returns {Promise<void>}
   */
  private async sendSlack(webhookUrl: string, event: SecurityEvent): Promise<void> {
    try {
      const payload = {
        attachments: [
          {
            color: this.getSlackColor(event.severity),
            title: `🚨 ${event.title}`,
            text: event.description,
            fields: [
              {
                title: 'Event Type',
                value: event.type,
                short: true,
              },
              {
                title: 'Severity',
                value: event.severity.toUpperCase(),
                short: true,
              },
              {
                title: 'User ID',
                value: event.userId,
                short: true,
              },
              {
                title: 'Timestamp',
                value: new Date().toISOString(),
                short: true,
              },
              {
                title: 'Metadata',
                value: event.metadata 
                  ? `\`\`\`${JSON.stringify(event.metadata, null, 2)}\`\`\`` 
                  : '_No metadata provided_',
                short: false,
              },
            ],
            footer: 'Arniko Security',
            ts: Math.floor(Date.now() / 1000),
          },
        ],
      };

      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
    } catch (error) {
      console.error(`[AlertService] Slack delivery failed:`, error);
      // Fail silently to prevent disrupting other channels
    }
  }

  /**
   * Maps internal severity levels to PagerDuty severity levels.
   * @private
   * @param {string} severity - Internal severity string
   * @returns {string} PagerDuty severity (critical, error, warning, info)
   */
  private mapToPagerDutySeverity(severity: string): string {
    const normalized = severity.toLowerCase();
    switch (normalized) {
      case 'critical':
        return 'critical';
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
      case 'info':
      default:
        return 'info';
    }
  }

  /**
   * Triggers a PagerDuty incident via Events API v2.
   * @private
   * @param {string} integrationKey - PagerDuty integration/routing key
   * @param {SecurityEvent} event - Security event data
   * @returns {Promise<void>}
   */
  private async sendPagerDuty(integrationKey: string, event: SecurityEvent): Promise<void> {
    try {
      const payload = {
        routing_key: integrationKey,
        event_action: 'trigger',
        payload: {
          summary: `[${event.severity.toUpperCase()}] ${event.title}`,
          severity: this.mapToPagerDutySeverity(event.severity),
          source: 'arniko-security-service',
          timestamp: new Date().toISOString(),
          component: event.type,
          custom_details: {
            description: event.description,
            user_id: event.userId,
            metadata: event.metadata || {},
          },
        },
      };

      const response = await fetch('https://events.pagerduty.com/v2/enqueue', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => 'Unknown error');
        throw new Error(`HTTP ${response.status}: ${errorBody}`);
      }
    } catch (error) {
      console.error(`[AlertService] PagerDuty delivery failed:`, error);
      // Fail silently to prevent disrupting other channels
    }
  }

  /**
   * Sends email notification via Resend API.
   * @private
   * @param {SecurityEvent} event - Security event data
   * @returns {Promise<void>}
   */
  private async sendEmailViaResend(event: SecurityEvent): Promise<void> {
    if (!this.config.resend) return;

    try {
      const result = await sendSecurityAlert(
        event,
        this.config.email?.to,
        this.config.resend.from
      );

      if (!result.success) {
        console.error(`[AlertService] Resend email failed: ${result.error}`);
      }
    } catch (error) {
      console.error(`[AlertService] Email delivery failed:`, error);
      // Fail silently to prevent disrupting other channels
    }
  }

  /**
   * Legacy email notification that uses environment-based Resend configuration.
   * Falls back to console logging if Resend is not configured.
   * @private
   * @param {string[]} to - Array of recipient email addresses
   * @param {SecurityEvent} event - Security event data
   * @param {string} [from] - Optional sender email
   * @returns {Promise<void>}
   */
  private async sendEmailLegacy(to: string[], event: SecurityEvent, from?: string): Promise<void> {
    try {
      const result = await sendSecurityAlert(event, to, from);

      if (!result.success && result.error) {
        console.error(`[AlertService] Email delivery failed: ${result.error}`);
      }
    } catch (error) {
      console.error(`[AlertService] Email delivery failed:`, error);
      // Fail silently to prevent disrupting other channels
    }
  }
}

/**
 * Factory function to create an AlertService instance.
 * Provides a convenient way to instantiate the service with configuration.
 * 
 * @param {AlertServiceConfig} config - Configuration for alert channels
 * @returns {AlertService} Configured AlertService instance
 * 
 * @example
 * ```typescript
 * const alertService = createAlertService({
 *   slack: { webhookUrl: process.env.SLACK_WEBHOOK_URL },
 *   pagerduty: { integrationKey: process.env.PD_INTEGRATION_KEY },
 *   resend: { apiKey: process.env.RESEND_API_KEY, from: 'security@arniko.io' },
 *   email: { to: ['security@arniko.io'] }
 * });
 * 
 * await alertService.sendAlert({
 *   type: 'suspicious_login',
 *   severity: 'high',
 *   title: 'Suspicious login detected',
 *   description: 'Multiple failed attempts followed by successful login from new IP',
 *   userId: 'user_12345',
 *   metadata: { ip: '192.168.1.1', userAgent: 'Mozilla/5.0...' }
 * });
 * ```
 */
export function createAlertService(config: AlertServiceConfig): AlertService {
  return new AlertService(config);
}
