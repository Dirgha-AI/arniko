/**
 * Semgrep Scanner Adapter
 *
 * Runs Semgrep static analysis for security vulnerabilities.
 * Uses security-focused rulesets from Semgrep registry.
 *
 * Requires: semgrep (pip install semgrep)
 * Falls back to mock results in dev if not installed.
 */

import { spawn } from 'child_process';
import { randomUUID } from 'crypto';
import type { ScanResult, ScanStatus, ScanTarget, SemgrepConfig, SemgrepFinding, ScanSeverity } from '../types/index.js';

const DEFAULT_RULES = [
  'p/security-audit',
  'p/secrets',
  'p/owasp-top-ten',
  'p/javascript',
  'p/typescript',
];

interface SemgrepRawResult {
  check_id?: string;
  path?: string;
  start?: { line?: number; col?: number };
  extra?: {
    severity?: string;
    message?: string;
    lines?: string;
    metadata?: {
      fix?: string;
      cwe?: string;
      owasp?: string;
    };
  };
}

export class SemgrepScanner {
  private config: SemgrepConfig;

  constructor(config: SemgrepConfig) {
    this.config = {
      maxFileSize: 1_000_000,
      ...config,
      rules: config.rules ?? DEFAULT_RULES,
    };
  }

  async run(target: ScanTarget): Promise<ScanResult> {
    const scanId = randomUUID();
    const startedAt = new Date();

    try {
      const available = await this.checkInstalled();
      if (!available) {
        console.warn('[Semgrep] CLI not found, using simulation mode');
        return this.simulateScan(scanId, target, startedAt);
      }

      const findings = await this.runCLI();
      const completedAt = new Date();

      return {
        scanId,
        status: 'completed' as ScanStatus,
        tool: 'semgrep',
        target,
        findings,
        startedAt,
        completedAt,
        durationMs: completedAt.getTime() - startedAt.getTime(),
      };
    } catch (error) {
      return {
        scanId,
        status: 'failed' as ScanStatus,
        tool: 'semgrep',
        target,
        findings: [],
        startedAt,
        completedAt: new Date(),
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  private async checkInstalled(): Promise<boolean> {
    return new Promise((resolve) => {
      const proc = spawn('semgrep', ['--version'], { stdio: 'pipe' });
      proc.on('close', (code: number | null) => resolve(code === 0));
      proc.on('error', () => resolve(false));
    });
  }

  private async runCLI(): Promise<SemgrepFinding[]> {
    const args: string[] = [
      '--config', this.config.rules.join(','),
      '--json',
      '--no-git-ignore',
    ];

    if (this.config.excludePatterns?.length) {
      for (const pattern of this.config.excludePatterns) {
        args.push('--exclude', pattern);
      }
    }

    if (this.config.maxFileSize) {
      args.push('--max-target-bytes', String(this.config.maxFileSize));
    }

    args.push(this.config.path);

    return new Promise((resolve, reject) => {
      let stdout = '';
      const proc = spawn('semgrep', args, { stdio: ['ignore', 'pipe', 'pipe'] });
      proc.stdout?.on('data', (d: Buffer) => { stdout += d.toString(); });

      proc.on('close', () => {
        try {
          const output = JSON.parse(stdout || '{"results":[]}') as { results?: SemgrepRawResult[] };
          resolve((output.results || []).map((r: SemgrepRawResult) => this.parseResult(r)));
        } catch {
          resolve([]);
        }
      });

      proc.on('error', (err: Error) => reject(err));
    });
  }

  private parseResult(raw: SemgrepRawResult): SemgrepFinding {
    const severity = ((): ScanSeverity => {
      const s = String(raw.extra?.severity || 'medium').toLowerCase();
      if (s === 'error') return 'high';
      if (s === 'warning') return 'medium';
      return 'low';
    })();

    const start = raw.start || {};
    const metadata = raw.extra?.metadata || {};

    return {
      id: randomUUID(),
      tool: 'semgrep',
      severity,
      title: String(raw.check_id || 'Semgrep Finding'),
      description: String(raw.extra?.message || ''),
      remediation: metadata?.fix || undefined,
      evidence: String(raw.extra?.lines || ''),
      location: {
        file: String(raw.path || ''),
        line: start.line,
        column: start.col,
      },
      cwe: metadata?.cwe,
      owasp: metadata?.owasp,
      ruleId: String(raw.check_id || ''),
      ruleMessage: String(raw.extra?.message || ''),
      fix: metadata?.fix || undefined,
    };
  }

  private simulateScan(scanId: string, target: ScanTarget, startedAt: Date): ScanResult {
    return {
      scanId,
      status: 'completed',
      tool: 'semgrep',
      target,
      findings: [{
        id: randomUUID(),
        tool: 'semgrep',
        severity: 'medium',
        title: 'Simulation: Install semgrep for real SAST analysis',
        description: 'Run: pip install semgrep',
        metadata: { simulated: true, ruleId: 'arniko.simulation', ruleMessage: 'Semgrep not installed' },
      }],
      startedAt,
      completedAt: new Date(),
      durationMs: 50,
      metadata: { simulated: true },
    };
  }
}

export function createSemgrepScanner(config: SemgrepConfig): SemgrepScanner {
  return new SemgrepScanner(config);
}
