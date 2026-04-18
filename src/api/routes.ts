
import { Hono, Context } from 'hono';
import { z } from 'zod';
import { ScanOrchestrator, ArnikoOrchestrator } from '../orchestrator.js';
import type { ArnikoConfig } from '../orchestrator.js';
import { ArnikoDb } from '../db/client.js';
import { randomUUID } from 'crypto';

// Minimal zValidator shim (replaces @hono/zod-validator)
function zValidator<T extends z.ZodTypeAny>(target: 'json', schema: T) {
  return async (c: Context, next: () => Promise<void>): Promise<void | Response> => {
    const body = await c.req.json().catch(() => ({}));
    const result = schema.safeParse(body);
    if (!result.success) { await c.json({ error: result.error.issues }, 400); return; }
    (c as any)._validData = { json: result.data };
    await next();
  };
}

// Validation schema for scan requests
const ScanRequestSchema = z.object({
  targetType: z.enum(['repo', 'container', 'llm', 'api', 'iac']),
  targetId: z.string(),
  tools: z.array(z.string()).optional(),
  config: z.any().optional()
});

// Helper to extract user ID from header
const getUserId = (c: Context): string => c.req.header('x-user-id') || 'anonymous';

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

// Initialize router
const router = new Hono();

// 1. POST / — Start a scan
router.post('/', zValidator('json', ScanRequestSchema), async (c) => {
  const db = getDb();
  const config: ArnikoConfig = { scanners: {} };
  const orchestrator = new ArnikoOrchestrator(config);
  const userId = getUserId(c);
  const body = await c.req.json() as any;

  // Create scan record in database
  const scan = await db.createScan(userId, body.targetType, body.targetId, body.tools || []);

  // Trigger scan asynchronously
  orchestrator.startScan(userId, body.targetType, body.targetId, body.tools || []).catch((err: Error) => {
    console.error(`Scan ${scan.id} failed:`, err);
    db.updateScanStatus(scan.id, 'failed', undefined, err.message);
  });
  
  return c.json({ 
    scanId: scan.id, 
    status: 'pending', 
    message: 'Scan started' 
  });
});

// 2. GET /:id — Real scan status from DB
router.get('/:id', async (c) => {
  const db = getDb();
  const userId = getUserId(c);
  const scanId = c.req.param('id');
  
  const scans = await db.getScans(userId, 100);
  const scan = scans.find(s => s.id === scanId);
  
  if (!scan) {
    return c.json({ error: 'Scan not found' }, 404);
  }
  
  return c.json({
    scanId: scan.id,
    status: scan.status,
    durationMs: scan.duration_ms,
    tools: scan.tools,
    startedAt: scan.created_at,
    completedAt: scan.updated_at,
    error: scan.error
  });
});

// 3. GET /:id/findings — Real findings from DB
router.get('/:id/findings', async (c) => {
  const db = getDb();
  const scanId = c.req.param('id');
  
  const findings = await db.getFindings(scanId);
  
  // Aggregate by severity
  const severityCounts = findings.reduce((acc, finding) => {
    const sev = finding.severity || 'info';
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  
  const bySeverity = {
    critical: severityCounts.critical || 0,
    high: severityCounts.high || 0,
    medium: severityCounts.medium || 0,
    low: severityCounts.low || 0,
    info: severityCounts.info || 0
  };
  
  // Aggregate by tool
  const byTool = findings.reduce((acc, finding) => {
    const tool = finding.tool || 'unknown';
    acc[tool] = (acc[tool] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  
  return c.json({ 
    scanId, 
    findings, 
    summary: { 
      total: findings.length, 
      bySeverity, 
      byTool 
    } 
  });
});

// 4. GET /posture — Security posture score
router.get('/posture', async (c) => {
  const db = getDb();
  const userId = getUserId(c);
  
  const scans = await db.getScans(userId, 10);
  
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  
  // Aggregate findings from recent scans
  for (const scan of scans) {
    const findings = await db.getFindings(scan.id);
    for (const finding of findings) {
      if (finding.severity === 'critical') criticalCount++;
      else if (finding.severity === 'high') highCount++;
      else if (finding.severity === 'medium') mediumCount++;
    }
  }
  
  // Calculate score: 100 - (criticals * 20 + highs * 10 + mediums * 5)
  let overallScore = 100 - (criticalCount * 20 + highCount * 10 + mediumCount * 5);
  if (overallScore < 0) overallScore = 0;
  
  return c.json({ 
    userId, 
    overallScore, 
    criticalCount, 
    highCount, 
    mediumCount, 
    trend: 'stable', 
    lastUpdated: new Date() 
  });
});

// 5. GET /coverage — Scanner coverage status
router.get('/coverage', (c) => {
  const scanners = [
    { name: 'garak', status: 'active', description: 'LLM vulnerability scanner' },
    { name: 'semgrep', status: 'active', description: 'Static analysis for code' },
    { name: 'trufflehog', status: 'active', description: 'Secret detection' },
    { name: 'trivy', status: 'active', description: 'Container and filesystem scanner' },
    { name: 'bandit', status: 'active', description: 'Python security linter' },
    { name: 'codeql', status: 'partial', description: 'Semantic code analysis' },
    { name: 'gitleaks', status: 'active', description: 'Git secret scanning' },
    { name: 'checkov', status: 'active', description: 'IaC security scanner' },
    { name: 'falco', status: 'partial', description: 'Runtime security' },
    { name: 'grype', status: 'active', description: 'Container vulnerability scanner' },
    { name: 'nemoGuardrails', status: 'stub', description: 'LLM guardrails' },
    { name: 'purpleLlama', status: 'stub', description: 'Meta LLM security' },
    { name: 'promptfoo', status: 'active', description: 'LLM prompt testing' },
    { name: 'snyk', status: 'partial', description: 'Dependency security' },
    { name: 'socket', status: 'stub', description: 'Supply chain security' },
    { name: 'vigil', status: 'stub', description: 'LLM security scanner' },
    { name: 'owaspDependencyCheck', status: 'active', description: 'Dependency vulnerability check' },
    { name: 'llmGuard', status: 'stub', description: 'LLM input/output protection' },
    { name: 'rebuff', status: 'stub', description: 'Prompt injection detection' },
    { name: 'deepteam', status: 'stub', description: 'AI red teaming' },
    { name: 'agenticSecurity', status: 'stub', description: 'Agent security testing' },
    { name: 'indirectInjection', status: 'partial', description: 'Indirect prompt injection detection' },
    { name: 'toolAttestation', status: 'stub', description: 'Tool use verification' }
  ];
  
  return c.json({ scanners });
});

// 6. GET /:id/sarif — SARIF 2.1.0 format export
router.get('/:id/sarif', async (c) => {
  const db = getDb();
  const scanId = c.req.param('id');
  
  const findings = await db.getFindings(scanId);
  
  const mapSeverity = (severity: string): string => {
    switch (severity?.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'note';
      default:
        return 'note';
    }
  };
  
  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'Arniko',
          version: '1.0.0',
          informationUri: 'https://arniko.security'
        }
      },
      results: findings.map(f => ({
        ruleId: `${f.tool}-${f.cwe || 'UNKNOWN'}`,
        message: {
          text: f.description || 'No description provided'
        },
        level: mapSeverity(f.severity),
        locations: f.location ? [{
          physicalLocation: {
            artifactLocation: {
              uri: f.location
            },
          }
        }] : undefined
      }))
    }]
  };
  
  c.header('Content-Type', 'application/sarif+json');
  return c.json(sarif);
});

// Backward compatibility export
export const createScanRoutes = () => router;
export default router;

// Backward-compatible alias
export const createArnikoRoutes = createScanRoutes;
