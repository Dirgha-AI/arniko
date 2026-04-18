import { Hono } from 'hono';
// @ts-ignore - optional module
import { query } from '../db/helper';

const app = new Hono();

app.get('/stats', async (c) => {
  const { rows: [r] } = await query(`SELECT COUNT(*)::int as total_scans, COALESCE(SUM(critical_count),0)::int as critical_findings, COALESCE(SUM(high_count),0)::int as high_findings, COALESCE(SUM(medium_count),0)::int as medium_findings, ROUND(AVG(duration),2)::float as avg_scan_duration, COUNT(CASE WHEN created_at::date = CURRENT_DATE THEN 1 END)::int as scans_today, COUNT(CASE WHEN created_at >= DATE_TRUNC('week', CURRENT_DATE) THEN 1 END)::int as scans_this_week FROM scan_results`);
  return c.json(r);
});

app.get('/recent', async (c) => {
  const { rows } = await query(`SELECT target, type, json_build_object('critical', critical_count, 'high', high_count, 'medium', medium_count) as severity_counts, status, duration FROM scan_results ORDER BY created_at DESC LIMIT 10`);
  return c.json(rows);
});

app.get('/trends', async (c) => {
  const { rows } = await query(`SELECT to_char(DATE_TRUNC('week', created_at), 'YYYY-MM-DD') as week, COUNT(*)::int as count FROM scan_results WHERE created_at >= NOW() - INTERVAL '12 weeks' GROUP BY DATE_TRUNC('week', created_at) ORDER BY week DESC LIMIT 12`);
  return c.json(rows);
});

app.get('/top-vulnerabilities', async (c) => {
  const { rows } = await query(`SELECT vulnerability_type, COUNT(*)::int as count FROM findings GROUP BY vulnerability_type ORDER BY count DESC LIMIT 10`);
  return c.json(rows);
});

export default app;
