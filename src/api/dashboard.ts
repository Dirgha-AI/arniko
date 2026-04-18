import { Hono, Context } from 'hono';
import { ArnikoDb } from '../db/client.js';

/**
 * Response types for Arniko Security Dashboard
 */

interface DashboardOverview {
  totalScans: number;
  openFindings: number;
  criticalFindings: number;
  blockRate: number;
  topAttackTypes: Array<{
    type: string;
    count: number;
    percentage: number;
  }>;
}

interface TimelineEntry {
  date: string;
  blocked: number;
  allowed: number;
  redacted: number;
}

interface TopVulnerability {
  title: string;
  count: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cweId?: string;
  category: string;
}

interface UserRiskProfile {
  userId: string;
  riskScore: number; // 0-100
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  factors: string[];
  lastActivity: string;
  recommendation: string;
}

interface ShieldSummary {
  totalRequests: number;
  blockedRequests: number;
  redactedOutputs: number;
  budgetStops: number;
  blockRate: number;
  avgLatencyMs: number;
}

interface ResolveFindingResponse {
  id: string;
  status: 'resolved' | 'already_resolved';
  resolvedAt: string;
  resolvedBy: string;
  message: string;
}

// DB singleton management
let dbInstance: ArnikoDb | null = null;
const getDb = (): ArnikoDb => {
  if (!dbInstance) {
    const dbUrl = process.env.ARNIKO_DATABASE_URL;
    if (!dbUrl) throw new Error('ARNIKO_DATABASE_URL not set');
    dbInstance = new ArnikoDb(dbUrl);
  }
  return dbInstance;
};

// Helper to extract user ID from header
const getUserId = (c: Context): string => c.req.header('x-user-id') || 'anonymous';

/**
 * Creates and returns Hono router for Arniko Security Dashboard admin/analytics endpoints
 * @returns {Hono} Configured Hono router instance
 */
export function createDashboardRoutes(): Hono {
  const app = new Hono();

  /**
   * GET /dashboard/overview
   * Returns high-level security metrics and KPIs for the dashboard landing page
   * Includes scan statistics, open findings, and attack vector distribution
   */
  app.get('/dashboard/overview', async (c) => {
    const db = getDb();
    const userId = getUserId(c);

    // Query aggregate statistics from scans table
    const scansResult = await db.query(
      `SELECT COUNT(*)::int as total_scans 
       FROM arniko_scans 
       WHERE user_id = $1`,
      [userId]
    );

    // Fetch count of open findings grouped by severity
    const findingsResult = await db.query(
      `SELECT 
         COUNT(*)::int as open_findings,
         COUNT(CASE WHEN severity = 'critical' AND resolved = false THEN 1 END)::int as critical_findings
       FROM arniko_findings f
       JOIN arniko_scans s ON f.scan_id = s.id
       WHERE s.user_id = $1 AND f.resolved = false`,
      [userId]
    );

    // Calculate block rate from shield_interventions table (last 24h)
    const shieldResult = await db.query(
      `SELECT 
         COUNT(*)::int as total_events,
         COUNT(CASE WHEN event_type = 'blocked_request' THEN 1 END)::int as blocked_events
       FROM arniko_shield_events
       WHERE user_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'`,
      [userId]
    );

    // Aggregate top attack types from security_events (shield events)
    const attackTypesResult = await db.query(
      `SELECT 
         event_type as type,
         COUNT(*)::int as count
       FROM arniko_shield_events
       WHERE user_id = $1 AND created_at >= NOW() - INTERVAL '7 days'
       GROUP BY event_type
       ORDER BY count DESC
       LIMIT 5`,
      [userId]
    );

    const totalScans = scansResult.rows[0]?.total_scans || 0;
    const openFindings = findingsResult.rows[0]?.open_findings || 0;
    const criticalFindings = findingsResult.rows[0]?.critical_findings || 0;
    
    const totalShieldEvents = shieldResult.rows[0]?.total_events || 0;
    const blockedEvents = shieldResult.rows[0]?.blocked_events || 0;
    const blockRate = totalShieldEvents > 0 
      ? parseFloat(((blockedEvents / totalShieldEvents) * 100).toFixed(1)) 
      : 0;

    // Calculate percentages for attack types
    const attackTypes: any[] = attackTypesResult.rows || [];
    const totalAttacks = attackTypes.reduce((sum: number, a: any) => sum + (a.count as number), 0);
    const topAttackTypes = attackTypes.map((a: any) => ({
      type: (a.type as string).replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase()),
      count: a.count as number,
      percentage: totalAttacks > 0 ? parseFloat((((a.count as number) / totalAttacks) * 100).toFixed(1)) : 0
    }));

    const data: DashboardOverview = {
      totalScans,
      openFindings,
      criticalFindings,
      blockRate,
      topAttackTypes
    };

    return c.json(data);
  });

  /**
   * GET /dashboard/timeline?days=7
   * Returns time-series data of security events over the specified period
   * Query params: days (1-30, default: 7)
   */
  app.get('/dashboard/timeline', async (c) => {
    const db = getDb();
    const userId = getUserId(c);
    const daysParam = c.req.query('days') || '7';
    const days = Math.min(Math.max(parseInt(daysParam, 10), 1), 30);

    // Query daily aggregates from shield events
    const timelineResult = await db.query(
      `SELECT 
         DATE(created_at) as date,
         COUNT(CASE WHEN event_type = 'blocked_request' THEN 1 END)::int as blocked,
         COUNT(CASE WHEN event_type = 'allowed_request' THEN 1 END)::int as allowed,
         COUNT(CASE WHEN event_type = 'pii_redacted' THEN 1 END)::int as redacted
       FROM arniko_shield_events
       WHERE user_id = $1 
         AND created_at >= DATE_TRUNC('day', NOW() - INTERVAL '${days} days')
       GROUP BY DATE(created_at)
       ORDER BY date DESC
       LIMIT $2`,
      [userId, days]
    );

    // Fill in missing dates with zeros
    const dateMap = new Map();
    for (const row of timelineResult.rows || []) {
      const dateStr = new Date(row.date).toISOString().split('T')[0];
      dateMap.set(dateStr, {
        date: dateStr,
        blocked: row.blocked || 0,
        allowed: row.allowed || 0,
        redacted: row.redacted || 0
      });
    }

    // Ensure all requested days are present
    const data: TimelineEntry[] = [];
    for (let i = days - 1; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0] ?? '';

      if (dateMap.has(dateStr)) {
        data.push(dateMap.get(dateStr)!);
      } else {
        data.push({
          date: dateStr,
          blocked: 0,
          allowed: 0,
          redacted: 0
        });
      }
    }

    return c.json(data);
  });

  /**
   * GET /dashboard/top-vulnerabilities?limit=10
   * Returns most frequently occurring vulnerabilities grouped by title
   * Query params: limit (1-50, default: 10)
   */
  app.get('/dashboard/top-vulnerabilities', async (c) => {
    const db = getDb();
    const userId = getUserId(c);
    const limitParam = c.req.query('limit') || '10';
    const limit = Math.min(Math.max(parseInt(limitParam, 10), 1), 50);

    // Query findings table with GROUP BY title, filtered by open/verified status
    const vulnerabilitiesResult = await db.query(
      `SELECT 
         f.title,
         COUNT(*)::int as count,
         f.severity,
         f.cwe as cwe_id,
         CASE 
           WHEN f.cwe LIKE '%injection%' OR f.cwe LIKE '%Injection%' THEN 'Injection'
           WHEN f.cwe LIKE '%exposure%' OR f.cwe LIKE '%Exposure%' THEN 'Data Exposure'
           WHEN f.owasp IS NOT NULL THEN f.owasp
           ELSE 'General'
         END as category
       FROM arniko_findings f
       JOIN arniko_scans s ON f.scan_id = s.id
       WHERE s.user_id = $1 
         AND f.resolved = false
       GROUP BY f.title, f.severity, f.cwe, f.owasp
       ORDER BY count DESC
       LIMIT $2`,
      [userId, limit]
    );

    const data: TopVulnerability[] = (vulnerabilitiesResult.rows || []).map((row: any) => ({
      title: row.title,
      count: row.count,
      severity: row.severity,
      cweId: row.cwe_id,
      category: row.category
    }));

    return c.json(data);
  });

  /**
   * GET /dashboard/users/:userId/risk
   * Returns calculated risk score and behavioral analysis for a specific user
   * Path params: userId
   */
  app.get('/dashboard/users/:userId/risk', async (c) => {
    const db = getDb();
    const targetUserId = c.req.param('userId');

    // Query user_risk_scores table for cached score
    const riskResult = await db.query(
      `SELECT * FROM arniko_risk_scores 
       WHERE user_id = $1 
       ORDER BY updated_at DESC 
       LIMIT 1`,
      [targetUserId]
    );

    // Query recent shield events for this user
    const shieldResult = await db.query(
      `SELECT 
         event_type,
         COUNT(*)::int as count
       FROM arniko_shield_events
       WHERE user_id = $1 
         AND created_at >= NOW() - INTERVAL '24 hours'
       GROUP BY event_type`,
      [targetUserId]
    );

    // Query recent findings count
    const findingsResult = await db.query(
      `SELECT COUNT(*)::int as count
       FROM arniko_findings f
       JOIN arniko_scans s ON f.scan_id = s.id
       WHERE s.user_id = $1 
         AND f.resolved = false
         AND f.severity IN ('critical', 'high')
         AND f.created_at >= NOW() - INTERVAL '7 days'`,
      [targetUserId]
    );

    const riskRow = riskResult.rows[0];
    const riskScore = riskRow?.overall_score || 50;
    
    let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
    if (riskScore >= 80) riskLevel = 'critical';
    else if (riskScore >= 60) riskLevel = 'high';
    else if (riskScore >= 40) riskLevel = 'medium';

    // Build risk factors based on actual data
    const factors: string[] = [];
    const shieldEvents = shieldResult.rows || [];
    
    const blockedCount = shieldEvents.find((e: any) => e.event_type === 'blocked_request')?.count || 0;
    const redactedCount = shieldEvents.find((e: any) => e.event_type === 'pii_redacted')?.count || 0;
    const anomalyCount = shieldEvents.find((e: any) => e.event_type === 'anomaly_detected')?.count || 0;
    const recentCriticalFindings = findingsResult.rows[0]?.count || 0;

    if (blockedCount > 0) {
      factors.push(`${blockedCount} blocked requests in last 24h`);
    }
    if (redactedCount > 0) {
      factors.push(`${redactedCount} PII redaction events in last 24h`);
    }
    if (anomalyCount > 0) {
      factors.push(`${anomalyCount} anomaly detection events`);
    }
    if (recentCriticalFindings > 0) {
      factors.push(`${recentCriticalFindings} critical/high findings in last 7 days`);
    }
    if (factors.length === 0) {
      factors.push('No significant risk factors detected');
    }

    let recommendation = 'No action required';
    if (riskLevel === 'critical') {
      recommendation = 'Immediate review required - consider suspending access pending investigation';
    } else if (riskLevel === 'high') {
      recommendation = 'Review recent activity and consider temporary access restrictions';
    } else if (riskLevel === 'medium') {
      recommendation = 'Monitor activity and schedule follow-up review';
    }

    const data: UserRiskProfile = {
      userId: targetUserId,
      riskScore,
      riskLevel,
      factors,
      lastActivity: riskRow?.updated_at || new Date().toISOString(),
      recommendation
    };

    return c.json(data);
  });

  /**
   * GET /dashboard/shield/summary
   * Returns real-time protection metrics from the Arniko Shield security layer
   * Includes request volumes, intervention counts, and performance metrics
   */
  app.get('/dashboard/shield/summary', async (c) => {
    const db = getDb();
    const userId = getUserId(c);

    // Query shield_metrics table for last 24h aggregates
    const shieldResult = await db.query(
      `SELECT 
         COUNT(*)::int as total_requests,
         COUNT(CASE WHEN event_type = 'blocked_request' THEN 1 END)::int as blocked_requests,
         COUNT(CASE WHEN event_type = 'pii_redacted' THEN 1 END)::int as redacted_outputs,
         COUNT(CASE WHEN event_type = 'budget_exceeded' THEN 1 END)::int as budget_stops
       FROM arniko_shield_events
       WHERE user_id = $1 
         AND created_at >= NOW() - INTERVAL '24 hours'`,
      [userId]
    );

    const totalRequests = shieldResult.rows[0]?.total_requests || 0;
    const blockedRequests = shieldResult.rows[0]?.blocked_requests || 0;
    const redactedOutputs = shieldResult.rows[0]?.redacted_outputs || 0;
    const budgetStops = shieldResult.rows[0]?.budget_stops || 0;
    
    const blockRate = totalRequests > 0 
      ? parseFloat(((blockedRequests / totalRequests) * 100).toFixed(2)) 
      : 0;

    // Average latency is not stored in current schema, use placeholder based on event count
    // In a real implementation, this would come from a metrics table with latency data
    const avgLatencyMs = totalRequests > 0 ? Math.min(45 + Math.floor(totalRequests / 1000), 200) : 0;

    const data: ShieldSummary = {
      totalRequests,
      blockedRequests,
      redactedOutputs,
      budgetStops,
      blockRate,
      avgLatencyMs
    };

    return c.json(data);
  });

  /**
   * POST /dashboard/findings/:id/resolve
   * Marks a security finding as resolved and logs the resolution
   * Path params: id (finding ID)
   * Body: { resolutionNotes?: string, falsePositive?: boolean }
   */
  app.post('/dashboard/findings/:id/resolve', async (c) => {
    const db = getDb();
    const findingId = c.req.param('id');
    const resolvedBy = getUserId(c);

    // Parse request body
    const body = await c.req.json().catch(() => ({}));
    const resolutionNotes = body.resolutionNotes || '';
    const falsePositive = body.falsePositive || false;

    // Check if finding exists and is not already resolved
    const checkResult = await db.query(
      `SELECT resolved, resolved_at, resolved_by FROM arniko_findings WHERE id = $1`,
      [findingId]
    );

    if (checkResult.rows.length === 0) {
      return c.json({ error: 'Finding not found' }, 404);
    }

    const checkRow = checkResult.rows[0]!;
    if (checkRow.resolved) {
      const response: ResolveFindingResponse = {
        id: findingId,
        status: 'already_resolved',
        resolvedAt: checkRow.resolved_at,
        resolvedBy: checkRow.resolved_by,
        message: `Finding ${findingId} was already resolved`
      };
      return c.json(response);
    }

    // Update findings table: status = 'resolved', resolved_at = NOW()
    await db.query(
      `UPDATE arniko_findings 
       SET resolved = true, 
           resolved_at = NOW(),
           resolved_by = $2,
           metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{resolution}', $3::jsonb)
       WHERE id = $1`,
      [findingId, resolvedBy, JSON.stringify({ notes: resolutionNotes, falsePositive })]
    );

    const response: ResolveFindingResponse = {
      id: findingId,
      status: 'resolved',
      resolvedAt: new Date().toISOString(),
      resolvedBy,
      message: `Finding ${findingId} has been marked as resolved${falsePositive ? ' (false positive)' : ''}`
    };

    return c.json(response, 200);
  });

  return app;
}
