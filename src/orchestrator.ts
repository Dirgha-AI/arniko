import { randomUUID } from 'crypto';
import { eq, desc } from 'drizzle-orm';
import { drizzle, NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import * as schema from './db/schema.js';
import { GarakScanner } from './scanners/garak.js';
import { SemgrepScanner } from './scanners/semgrep.js';
import { LLMGuardScanner } from './scanners/llmGuard.js';
import { RebuffScanner } from './scanners/rebuff.js';
import { TrivyScanner } from './scanners/trivy.js';
import { BanditScanner } from './scanners/bandit.js';
import { CodeQLScanner } from './scanners/codeql.js';
import { GitLeaksScanner } from './scanners/gitleaks.js';
import { CheckovScanner } from './scanners/checkov.js';
import { FalcoScanner } from './scanners/falco.js';
import { GrypeScanner } from './scanners/grype.js';
import { NeMoGuardrailsScanner } from './scanners/nemoGuardrails.js';
import { PurpleLlamaScanner } from './scanners/purpleLlama.js';
import { PromptfooScanner } from './scanners/promptfoo.js';
import { SnykScanner } from './scanners/snyk.js';
import { SocketScanner } from './scanners/socket.js';
import { VigilScanner } from './scanners/vigil.js';
import { OWASPDependencyCheckScanner } from './scanners/owaspDependencyCheck.js';
import { TruffleHogScanner } from './scanners/trufflehog.js';
import { DeepTeamScanner } from './scanners/deepteam.js';
import { AgenticSecurityScanner } from './scanners/agenticSecurity.js';
import { IndirectInjectionScanner } from './scanners/indirectInjection.js';
import { ToolAttestationScanner } from './scanners/toolAttestation.js';
import { OwaspLlmTop10Scanner } from './scanners/owaspLlmTop10.js';
import { ModelProvenance } from './scanners/slsaModel.js';
import type { ScanTarget, ScanResult as ScannerResult } from './types/index.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyScanner = { run(...args: any[]): Promise<any> };

export interface ArnikoConfig {
  scanners: {
    [key: string]: { enabled: boolean; config?: any } | undefined;
    garak?: { enabled: boolean; config?: any };
    semgrep?: { enabled: boolean; config?: any };
    trufflehog?: { enabled: boolean; config?: any };
    trivy?: { enabled: boolean; config?: any };
    bandit?: { enabled: boolean; config?: any };
    codeql?: { enabled: boolean; config?: any };
    gitleaks?: { enabled: boolean; config?: any };
    checkov?: { enabled: boolean; config?: any };
    falco?: { enabled: boolean; config?: any };
    grype?: { enabled: boolean; config?: any };
    nemoGuardrails?: { enabled: boolean; config?: any };
    purpleLlama?: { enabled: boolean; config?: any };
    promptfoo?: { enabled: boolean; config?: any };
    snyk?: { enabled: boolean; config?: any };
    socket?: { enabled: boolean; config?: any };
    vigil?: { enabled: boolean; config?: any };
    owaspDependencyCheck?: { enabled: boolean; config?: any };
    llmGuard?: { enabled: boolean; config?: any };
    rebuff?: { enabled: boolean; config?: any };
    deepteam?: { enabled: boolean; config?: any };
  };
}

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface Finding {
  tool: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  message: string;
  file?: string;
  line?: number;
  rule?: string;
  [key: string]: any;
}

export interface ScanResult {
  scanId: string;
  status: ScanStatus;
  findings: Finding[];
  startedAt: Date;
  completedAt?: Date;
  error?: string;
  durationMs?: number;
}

export interface FindingsResponse {
  scanId: string;
  status: ScanStatus;
  findings: Finding[];
  count: number;
}

type DatabaseClient = NodePgDatabase<typeof schema>;

export class ArnikoOrchestrator {
  private config: ArnikoConfig;
  private db: DatabaseClient;

  /** Run any scanner and map ScanFinding[] → Finding[] */
  private async runAndMap(scanner: AnyScanner, targetId: string, targetType: string): Promise<Finding[]> {
    const raw = await scanner.run({ type: targetType as ScanTarget['type'], identifier: targetId });
    // Handle both ScanResult shape ({ findings: [...] }) and raw arrays
    const findings: ScannerResult['findings'] = Array.isArray(raw) ? raw : (raw?.findings ?? []);
    return findings.map((f: ScannerResult['findings'][number]) => ({
      tool: f.tool,
      severity: ((f.severity as string) === 'informational' ? 'info' : f.severity) as Finding['severity'],
      message: `${f.title}: ${f.description}`,
      file: f.location?.file,
      line: f.location?.line,
      rule: f.cwe,
      ...f.metadata,
    }));
  }

  constructor(config: ArnikoConfig, db?: DatabaseClient) {
    this.config = config;
    
    if (db) {
      this.db = db;
    } else {
      // Create default connection if not provided
      const connectionString = process.env.ARNIKO_DATABASE_URL || process.env.DATABASE_URL || '';
      if (!connectionString) {
        throw new Error('Database connection string required. Set ARNIKO_DATABASE_URL or DATABASE_URL env variable.');
      }
      const pool = new Pool({
        connectionString,
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
      });
      this.db = drizzle(pool, { schema });
    }
  }

  async startScan(
    userId: string,
    targetType: 'repository' | 'container' | 'llm' | 'infrastructure',
    targetId: string,
    tools: string[]
  ): Promise<string> {
    const scanId = randomUUID();
    const startedAt = new Date();

    // Create scan record in database
    await this.db.insert(schema.scans).values({
      id: scanId,
      userId,
      targetType,
      targetId,
      tools,
      status: 'running',
      createdAt: startedAt,
      updatedAt: startedAt,
    });

    // Run scanners asynchronously
    this.runScanners(scanId, targetType, targetId, tools, startedAt).catch(async (error) => {
      console.error(`Scan ${scanId} failed:`, error);
      const completedAt = new Date();
      const durationMs = completedAt.getTime() - startedAt.getTime();
      
      await this.db.update(schema.scans)
        .set({
          status: 'failed',
          error: error.message,
          durationMs,
          completedAt,
          updatedAt: completedAt,
        })
        .where(eq(schema.scans.id, scanId));
    });

    return scanId;
  }

  private async runScanners(
    scanId: string,
    targetType: string,
    targetId: string,
    tools: string[],
    startedAt: Date
  ): Promise<void> {
    const findings: Finding[] = [];
    const startTime = startedAt.getTime();

    try {
      for (const tool of tools) {
        if (!this.config.scanners[tool]?.enabled) continue;

        const toolFindings = await this.runScanner(tool, targetId, targetType);
        
        // Store findings in database
        if (toolFindings.length > 0) {
          for (const finding of toolFindings) {
            await this.db.insert(schema.findings).values({
              id: randomUUID(),
              scanId,
              tool: finding.tool,
              severity: finding.severity,
              message: finding.message,
              file: finding.file ?? null,
              line: finding.line ?? null,
              rule: finding.rule ?? null,
              metadata: finding,
            });
          }
        }
        
        findings.push(...toolFindings);
      }

      const completedAt = new Date();
      const durationMs = completedAt.getTime() - startTime;

      // Update scan status to completed
      await this.db.update(schema.scans)
        .set({
          status: 'completed',
          durationMs,
          completedAt,
          updatedAt: completedAt,
        })
        .where(eq(schema.scans.id, scanId));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const completedAt = new Date();
      const durationMs = completedAt.getTime() - startTime;

      // Update scan status to failed
      await this.db.update(schema.scans)
        .set({
          status: 'failed',
          error: errorMessage,
          durationMs,
          completedAt,
          updatedAt: completedAt,
        })
        .where(eq(schema.scans.id, scanId));
      
      throw error;
    }
  }

  private async runScanner(
    tool: string,
    targetId: string,
    targetType: string
  ): Promise<Finding[]> {
    const config = this.config.scanners[tool]?.config || {};

    switch (tool) {
      case 'garak': return this.runAndMap(new GarakScanner(config), targetId, targetType);
      case 'semgrep': return this.runAndMap(new SemgrepScanner(config), targetId, targetType);
      case 'trufflehog': return this.runAndMap(new TruffleHogScanner({ ...config, simulation: true }), targetId, targetType);
      case 'trivy': return this.runAndMap(new TrivyScanner(config), targetId, targetType);
      case 'bandit': return this.runAndMap(new BanditScanner(config), targetId, targetType);
      case 'codeql': return this.runAndMap(new CodeQLScanner(config), targetId, targetType);
      case 'gitleaks': return this.runAndMap(new GitLeaksScanner(config), targetId, targetType);
      case 'checkov': return this.runAndMap(new CheckovScanner(config), targetId, targetType);
      case 'falco': return this.runAndMap(new FalcoScanner(config), targetId, targetType);
      case 'grype': return this.runAndMap(new GrypeScanner(config), targetId, targetType);
      case 'nemoGuardrails': return this.runAndMap(new NeMoGuardrailsScanner(config), targetId, targetType);
      case 'purpleLlama': return this.runAndMap(new PurpleLlamaScanner(config), targetId, targetType);
      case 'promptfoo': return this.runAndMap(new PromptfooScanner(config), targetId, targetType);
      case 'snyk': return this.runAndMap(new SnykScanner(config), targetId, targetType);
      case 'socket': return this.runAndMap(new SocketScanner(config), targetId, targetType);
      case 'vigil': return this.runAndMap(new VigilScanner(config), targetId, targetType);
      case 'owasp-dependency-check': return this.runAndMap(new OWASPDependencyCheckScanner(config), targetId, targetType);
      case 'llm-guard': return this.runAndMap(new LLMGuardScanner(config), targetId, targetType);
      case 'rebuff': return this.runAndMap(new RebuffScanner(config), targetId, targetType);
      case 'deepteam': return this.runAndMap(new DeepTeamScanner(config), targetId, targetType);
      case 'agentic-security': return this.runAndMap(new AgenticSecurityScanner(config), targetId, targetType);
      case 'indirect-injection': return this.runAndMap(new IndirectInjectionScanner(config), targetId, targetType);
      case 'tool-attestation': return this.runAndMap(new ToolAttestationScanner(config), targetId, targetType);
      case 'owasp-llm-top10': return this.runAndMap(new OwaspLlmTop10Scanner(config), targetId, targetType);
      case 'slsa-model': return this.runAndMap(new ModelProvenance(config), targetId, targetType);
      default:
        return [];
    }
  }

  private isValidUUID(id: string): boolean {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
  }

  async getStatus(scanId: string): Promise<ScanStatus | null> {
    if (!this.isValidUUID(scanId)) return null;
    const result = await this.db.query.scans.findFirst({
      where: eq(schema.scans.id, scanId),
    });

    if (result) {
      return result.status as ScanStatus;
    }

    return null;
  }

  async getFindings(scanId: string): Promise<FindingsResponse | null> {
    if (!this.isValidUUID(scanId)) return null;
    const scan = await this.db.query.scans.findFirst({
      where: eq(schema.scans.id, scanId),
    });

    if (!scan) {
      return null;
    }

    const findingsResult = await this.db.query.findings.findMany({
      where: eq(schema.findings.scanId, scanId),
      orderBy: [
        // Order by severity: critical first
        desc(schema.findings.severity),
        desc(schema.findings.createdAt),
      ],
    });

    const findingsList: Finding[] = findingsResult.map(f => ({
      tool: f.tool,
      severity: f.severity as Finding['severity'],
      message: f.message,
      file: f.file ?? undefined,
      line: f.line ?? undefined,
      rule: f.rule ?? undefined,
      ...(f.metadata || {}),
    }));

    return {
      scanId,
      status: scan.status as ScanStatus,
      findings: findingsList,
      count: findingsList.length,
    };
  }

  async isComplete(scanId: string): Promise<boolean> {
    if (!this.isValidUUID(scanId)) return false;
    const scan = await this.db.query.scans.findFirst({
      where: eq(schema.scans.id, scanId),
    });

    if (scan) {
      return scan.status === 'completed' || scan.status === 'failed';
    }

    return false;
  }

  /**
   * Get scan details including duration and error information
   */
  async getScanDetails(scanId: string): Promise<ScanResult | null> {
    const scan = await this.db.query.scans.findFirst({
      where: eq(schema.scans.id, scanId),
      with: {
        findings: true,
      },
    });

    if (!scan) {
      return null;
    }

    return {
      scanId: scan.id,
      status: scan.status as ScanStatus,
      findings: (scan.findings || []).map(f => ({
        tool: f.tool,
        severity: f.severity as Finding['severity'],
        message: f.message,
        file: f.file ?? undefined,
        line: f.line ?? undefined,
        rule: f.rule ?? undefined,
        ...(f.metadata || {}),
      })),
      startedAt: scan.createdAt ?? new Date(),
      completedAt: scan.completedAt ?? undefined,
      error: scan.error ?? undefined,
      durationMs: scan.durationMs ?? undefined,
    };
  }

  /**
   * List scans for a user with optional pagination
   */
  async listScans(userId: string, limit: number = 20): Promise<ScanResult[]> {
    const scansResult = await this.db.query.scans.findMany({
      where: eq(schema.scans.userId, userId),
      orderBy: [desc(schema.scans.createdAt)],
      limit,
    });

    return scansResult.map(scan => ({
      scanId: scan.id,
      status: scan.status as ScanStatus,
      findings: [], // Not loading findings for list view
      startedAt: scan.createdAt ?? new Date(),
      completedAt: scan.completedAt ?? undefined,
      error: scan.error ?? undefined,
      durationMs: scan.durationMs ?? undefined,
    }));
  }
}

// Backward-compatible alias
export { ArnikoOrchestrator as ScanOrchestrator };
