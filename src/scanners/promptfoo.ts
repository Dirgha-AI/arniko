import { spawn } from 'child_process';
import { randomUUID } from 'crypto';
import type { ScanFinding, ScanResult, ScanTarget, ScanStatus } from '../types/index.js';

export interface PromptfooConfig {
  timeoutMs?: number;
  checks?: string[];
}

export class PromptfooScanner {
  private timeoutMs: number;
  private checks: string[];

  constructor(config: PromptfooConfig) {
    this.timeoutMs = config.timeoutMs ?? 60_000;
    this.checks = config.checks ?? [];
  }

  async run(target: ScanTarget): Promise<ScanResult> {
    const scanId = randomUUID();
    const startedAt = new Date();

    const available = await this.checkInstalled();

    if (!available) {
      console.warn('[Promptfoo] CLI not found, using simulation mode');
      return {
        scanId,
        status: 'completed' as ScanStatus,
        tool: 'custom',
        target,
        findings: [
          {
            id: randomUUID(),
            tool: 'custom',
            severity: 'medium',
            title: 'Prompt injection vulnerability',
            description: 'Simulation: endpoint may be susceptible to prompt injection. Install promptfoo for real probing.',
            remediation: 'Run `npx promptfoo redteam` against the endpoint and review results.',
            metadata: { simulated: true },
          },
          {
            id: randomUUID(),
            tool: 'custom',
            severity: 'medium',
            title: 'Harmful output bypass',
            description: 'Simulation: endpoint may produce harmful outputs when adversarial prompts are supplied.',
            remediation: 'Add output filtering and content moderation layer.',
            metadata: { simulated: true },
          },
        ] satisfies ScanFinding[],
        startedAt,
        completedAt: new Date(),
        durationMs: 0,
        metadata: { simulated: true, reason: 'promptfoo_not_installed' },
      };
    }

    try {
      const findings = await this.runCLI(target);
      const completedAt = new Date();
      return {
        scanId,
        status: 'completed' as ScanStatus,
        tool: 'custom',
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
        tool: 'custom',
        target,
        findings: [],
        startedAt,
        completedAt: new Date(),
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  private checkInstalled(): Promise<boolean> {
    return new Promise((resolve) => {
      const p = spawn('npx', ['promptfoo', '--version'], { shell: true, stdio: 'pipe' });
      const t = setTimeout(() => { p.kill(); resolve(false); }, 5_000);
      p.on('error', () => { clearTimeout(t); resolve(false); });
      p.on('exit', (code) => { clearTimeout(t); resolve(code === 0); });
    });
  }

  private runCLI(target: ScanTarget): Promise<ScanFinding[]> {
    return new Promise((resolve, reject) => {
      const args = ['promptfoo', 'redteam', '--target', target.identifier, '--output', 'json'];
      const p = spawn('npx', args, { shell: true, stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      const t = setTimeout(() => { p.kill(); reject(new Error('Promptfoo timeout')); }, this.timeoutMs);
      p.stdout?.on('data', (d: Buffer) => { out += d.toString(); });
      p.on('error', (e) => { clearTimeout(t); reject(e); });
      p.on('exit', (code) => {
        clearTimeout(t);
        if (code !== 0 && code !== null) { reject(new Error(`promptfoo exited with code ${code}`)); return; }
        try {
          const data = JSON.parse(out);
          const results: unknown[] = Array.isArray(data?.results) ? data.results : [];
          resolve(results.map((x) => {
            const r = x as Record<string, unknown>;
            return {
              id: randomUUID(),
              tool: 'custom',
              severity: r.grade === 'fail' ? 'high' : 'medium',
              title: (r.description as string) || (r.test as Record<string, unknown>)?.description as string || 'Promptfoo finding',
              description: JSON.stringify(r).slice(0, 500),
              remediation: 'See promptfoo redteam report for details.',
              metadata: { raw: r },
            } satisfies ScanFinding;
          }));
        } catch (e) { reject(e); }
      });
    });
  }
}

export function createPromptfooScanner(config: PromptfooConfig): PromptfooScanner {
  return new PromptfooScanner(config);
}
