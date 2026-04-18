// @ts-ignore - optional module
import { query } from "./gateway/services/neon";

interface ScanResult {
  id?: string;
  target: string;
  scan_type: string;
  findings: any;
  severity_counts: any;
  started_at: Date;
  completed_at: Date;
  status: string;
}

export class ScanPersistence {
  async initTables(): Promise<void> {
    await query(`CREATE TABLE IF NOT EXISTS scan_results (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), target TEXT, scan_type TEXT, findings JSONB, severity_counts JSONB, started_at TIMESTAMPTZ, completed_at TIMESTAMPTZ, status TEXT)`);
    await query(`CREATE TABLE IF NOT EXISTS scan_history (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), scan_id UUID REFERENCES scan_results(id), event TEXT, data JSONB, timestamp TIMESTAMPTZ DEFAULT NOW())`);
  }

  async saveScanResult(result: ScanResult): Promise<string> {
    const { rows } = await query(`INSERT INTO scan_results (target, scan_type, findings, severity_counts, started_at, completed_at, status) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`, [result.target, result.scan_type, result.findings, result.severity_counts, result.started_at, result.completed_at, result.status]);
    return rows[0].id;
  }

  async getScanHistory(target: string, limit?: number): Promise<ScanResult[]> {
    const { rows } = await query(`SELECT * FROM scan_results WHERE target=$1 ORDER BY completed_at DESC LIMIT $2`, [target, limit || 100]);
    return rows;
  }

  async getStats(): Promise<{totalScans: number, criticalFindings: number, avgDuration: number}> {
    const { rows } = await query(`SELECT COUNT(*) as total, COALESCE(SUM((severity_counts->>'critical')::int),0) as critical, COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at-started_at))),0) as avg FROM scan_results`);
    return { totalScans: parseInt(rows[0].total), criticalFindings: parseInt(rows[0].critical), avgDuration: parseFloat(rows[0].avg) };
  }
}
