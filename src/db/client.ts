import { Pool, QueryResult } from 'pg';

// Type definitions for table rows
export interface ArnikoScan {
  id: string;
  user_id: string;
  target_type: string;
  target_id: string;
  tools: string[];
  status: 'pending' | 'running' | 'completed' | 'failed';
  duration_ms?: number;
  error?: string;
  created_at: Date;
  updated_at: Date;
}

export interface ArnikoFinding {
  id: string;
  scan_id: string;
  tool: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  remediation?: string;
  evidence?: string;
  location?: string;
  cwe?: string;
  owasp?: string;
  created_at: Date;
}

export interface ArnikoShieldEvent {
  id: string;
  user_id: string;
  event_type: string;
  severity: string;
  input_hash: string;
  reason: string;
  created_at: Date;
}

export interface ArnikoRiskScore {
  user_id: string;
  app_id: string;
  overall: number;
  injection: number;
  pii: number;
  cost: number;
  secret: number;
  trend: 'up' | 'down' | 'stable';
  updated_at: Date;
}

export interface FindingInput {
  tool: string;
  severity: string;
  title: string;
  description: string;
  remediation?: string;
  evidence?: string;
  location?: string;
  cwe?: string;
  owasp?: string;
}

export interface RiskScores {
  overall: number;
  injection: number;
  pii: number;
  cost: number;
  secret: number;
}

export class ArnikoDb {
  private pool: Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({
      connectionString,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });
  }

  async createScan(
    userId: string,
    targetType: string,
    targetId: string,
    tools: string[]
  ): Promise<ArnikoScan> {
    const query = `
      INSERT INTO arniko_scans (user_id, target_type, target_id, tools, status)
      VALUES ($1, $2, $3, $4, 'pending')
      RETURNING *
    `;
    const result: QueryResult<ArnikoScan> = await this.pool.query(query, [
      userId,
      targetType,
      targetId,
      tools,
    ]);
    return result.rows[0]!;
  }

  async updateScanStatus(
    scanId: string,
    status: string,
    durationMs?: number,
    error?: string
  ): Promise<void> {
    const query = `
      UPDATE arniko_scans 
      SET status = $1, 
          duration_ms = $2, 
          error = $3,
          updated_at = NOW()
      WHERE id = $4
    `;
    await this.pool.query(query, [status, durationMs, error, scanId]);
  }

  async insertFinding(
    scanId: string,
    finding: FindingInput
  ): Promise<ArnikoFinding> {
    const query = `
      INSERT INTO arniko_findings 
        (scan_id, tool, severity, title, description, remediation, evidence, location, cwe, owasp)
      VALUES 
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *
    `;
    const values = [
      scanId,
      finding.tool,
      finding.severity,
      finding.title,
      finding.description,
      finding.remediation ?? null,
      finding.evidence ?? null,
      finding.location ?? null,
      finding.cwe ?? null,
      finding.owasp ?? null,
    ];
    const result: QueryResult<ArnikoFinding> = await this.pool.query(query, values);
    return result.rows[0]!;
  }

  async insertShieldEvent(
    userId: string,
    eventType: string,
    severity: string,
    inputHash: string,
    reason: string
  ): Promise<ArnikoShieldEvent> {
    const query = `
      INSERT INTO arniko_shield_events 
        (user_id, event_type, severity, input_hash, reason)
      VALUES 
        ($1, $2, $3, $4, $5)
      RETURNING *
    `;
    const result: QueryResult<ArnikoShieldEvent> = await this.pool.query(query, [
      userId,
      eventType,
      severity,
      inputHash,
      reason,
    ]);
    return result.rows[0]!;
  }

  async getFindings(scanId: string): Promise<ArnikoFinding[]> {
    const query = `
      SELECT * FROM arniko_findings 
      WHERE scan_id = $1 
      ORDER BY 
        CASE severity
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          ELSE 5
        END,
        created_at DESC
    `;
    const result: QueryResult<ArnikoFinding> = await this.pool.query(query, [scanId]);
    return result.rows;
  }

  async getShieldEvents(
    userId: string,
    limit: number = 50
  ): Promise<ArnikoShieldEvent[]> {
    const query = `
      SELECT * FROM arniko_shield_events 
      WHERE user_id = $1 
      ORDER BY created_at DESC 
      LIMIT $2
    `;
    const result: QueryResult<ArnikoShieldEvent> = await this.pool.query(query, [
      userId,
      limit,
    ]);
    return result.rows;
  }

  async updateRiskScore(
    userId: string,
    appId: string,
    scores: RiskScores,
    trend: string
  ): Promise<ArnikoRiskScore> {
    const query = `
      INSERT INTO arniko_risk_scores 
        (user_id, app_id, overall, injection, pii, cost, secret, trend, updated_at)
      VALUES 
        ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      ON CONFLICT (user_id, app_id) 
      DO UPDATE SET 
        overall = EXCLUDED.overall,
        injection = EXCLUDED.injection,
        pii = EXCLUDED.pii,
        cost = EXCLUDED.cost,
        secret = EXCLUDED.secret,
        trend = EXCLUDED.trend,
        updated_at = NOW()
      RETURNING *
    `;
    const values = [
      userId,
      appId,
      scores.overall,
      scores.injection,
      scores.pii,
      scores.cost,
      scores.secret,
      trend,
    ];
    const result: QueryResult<ArnikoRiskScore> = await this.pool.query(query, values);
    return result.rows[0]!;
  }

  async getScans(userId: string, limit: number = 20): Promise<ArnikoScan[]> {
    const query = `
      SELECT * FROM arniko_scans 
      WHERE user_id = $1 
      ORDER BY created_at DESC 
      LIMIT $2
    `;
    const result: QueryResult<ArnikoScan> = await this.pool.query(query, [
      userId,
      limit,
    ]);
    return result.rows;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  /**
   * Execute a raw SQL query with parameters
   * Used by dashboard API for complex aggregate queries
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async query<T extends Record<string, any> = Record<string, any>>(sql: string, params?: any[]): Promise<QueryResult<T>> {
    return this.pool.query<T>(sql, params);
  }
}

// Singleton instance
export const db = new ArnikoDb(process.env.ARNIKO_DATABASE_URL || '');
