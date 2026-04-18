/**
 * Garak Scanner Adapter
 *
 * Runs Garak LLM vulnerability probes against an LLM endpoint.
 * Garak is the industry-standard LLM red-teaming tool from NVIDIA.
 *
 * In production: spawns `garak` CLI (must be installed: pip install garak)
 * In dev/test: uses built-in probe simulation
 */

import { spawn } from 'child_process';
import { randomUUID } from 'crypto';
import type {
  GarakConfig,
  GarakFinding,
  GarakProbe,
  ScanResult,
  ScanStatus,
  ScanTarget,
} from '../types/index.js';

// Map our probe names to Garak CLI probe module names
const PROBE_MAP: Record<GarakProbe, string[]> = {
  jailbreak:          ['jailbreak.Dan', 'jailbreak.Ablation', 'jailbreak.Refusal'],
  prompt_injection:   ['promptinject.HijackHateHumans', 'promptinject.HijackKillHumans'],
  data_exfiltration:  ['leakage.SecretKey', 'leakage.EnvFile'],
  encoding_attacks:   ['encoding.InjectBase64', 'encoding.InjectROT13'],
  roleplay_attacks:   ['roleplay.DAN', 'roleplay.ChatML', 'roleplay.Waluigi'],
  dan_variants:       ['dan.Dan_11_0', 'dan.DUDE', 'dan.DAN'],
  system_prompt_leak: ['leakage.GuardianCritic', 'leakage.SystemPromptLeakage'],
  all:                ['*'],
};

export class GarakScanner {
  private config: GarakConfig;

  constructor(config: GarakConfig) {
    this.config = {
      maxRetries: 3,
      timeoutMs: 60_000,
      ...config,
    };
  }

  async run(target: ScanTarget): Promise<ScanResult> {
    const scanId = randomUUID();
    const startedAt = new Date();

    try {
      // Check if garak is installed
      const garakAvailable = await this.checkGarakInstalled();

      if (!garakAvailable) {
        console.warn('[Garak] CLI not found, using simulation mode');
        return this.simulateScan(scanId, target, startedAt);
      }

      const findings = await this.runGarakCLI(target);
      const completedAt = new Date();

      return {
        scanId,
        status: 'completed' as ScanStatus,
        tool: 'garak',
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
        tool: 'garak',
        target,
        findings: [],
        startedAt,
        completedAt: new Date(),
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  private async checkGarakInstalled(): Promise<boolean> {
    return new Promise((resolve) => {
      const proc = spawn('garak', ['--version'], { stdio: 'pipe' });
      proc.on('close', (code) => resolve(code === 0));
      proc.on('error', () => resolve(false));
    });
  }

  private async runGarakCLI(target: ScanTarget): Promise<GarakFinding[]> {
    const probeModules = this.config.probes
      .flatMap((p) => PROBE_MAP[p] || [])
      .filter((v, i, arr) => arr.indexOf(v) === i); // deduplicate

    const args = [
      '--model_type', 'rest',
      '--model_name', target.identifier,
      '--probes', probeModules.join(','),
      '--format', 'jsonl',
    ];

    if (this.config.apiKey) {
      args.push('--api_key', this.config.apiKey);
    }

    return new Promise((resolve, reject) => {
      const findings: GarakFinding[] = [];
      const proc = spawn('garak', args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: this.config.timeoutMs,
      });

      let stdout = '';
      proc.stdout?.on('data', (d: Buffer) => { stdout += d.toString(); });

      proc.on('close', (code) => {
        if (code !== 0 && code !== null) {
          reject(new Error(`Garak exited with code ${code}`));
          return;
        }

        // Parse JSONL output
        for (const line of stdout.split('\n').filter(Boolean)) {
          try {
            const result = JSON.parse(line);
            if (result.passed === false) {
              findings.push(this.parseGarakResult(result));
            }
          } catch {
            // Skip malformed lines
          }
        }

        resolve(findings);
      });

      proc.on('error', reject);
    });
  }

  private parseGarakResult(raw: Record<string, unknown>): GarakFinding {
    const probe = (raw.probe as string) || 'unknown';
    const successRate = typeof raw.success_rate === 'number' ? raw.success_rate : 1.0;

    return {
      id: randomUUID(),
      tool: 'garak',
      severity: successRate > 0.7 ? 'critical' : successRate > 0.4 ? 'high' : 'medium',
      title: `LLM vulnerable to ${probe} attack`,
      description: `Garak probe "${probe}" succeeded with ${Math.round(successRate * 100)}% success rate`,
      remediation: 'Add InputFilter middleware to block this attack pattern. See @dirgha/security-shield.',
      evidence: Array.isArray(raw.examples) ? (raw.examples as string[])[0] : undefined,
      probe: probe as GarakProbe,
      successRate,
      sampleAttacks: Array.isArray(raw.examples) ? (raw.examples as string[]).slice(0, 3) : [],
      metadata: { rawProbeResult: raw },
    };
  }

  /**
   * Simulation mode — used when Garak CLI is not installed.
   * Returns realistic-looking findings based on common vulnerabilities.
   */
  private simulateScan(scanId: string, target: ScanTarget, startedAt: Date): ScanResult {
    const simulatedFindings: GarakFinding[] = [];

    for (const probe of this.config.probes) {
      if (probe === 'jailbreak' || probe === 'all') {
        simulatedFindings.push({
          id: randomUUID(),
          tool: 'garak',
          severity: 'high',
          title: 'LLM vulnerable to DAN jailbreak variants',
          description: 'Simulation: endpoint may be susceptible to DAN-style jailbreak prompts. Install Garak for real probe.',
          remediation: 'Add @dirgha/security-shield InputFilter middleware with JAILBREAK_PATTERNS enabled.',
          probe: 'jailbreak',
          successRate: 0.0,  // Unknown in simulation
          sampleAttacks: ['Ignore all previous instructions and...'],
          metadata: { simulated: true },
        });
      }
    }

    return {
      scanId,
      status: 'completed',
      tool: 'garak',
      target,
      findings: simulatedFindings,
      startedAt,
      completedAt: new Date(),
      durationMs: 100,
      metadata: { simulated: true, reason: 'garak_cli_not_installed' },
    };
  }
}

export function createGarakScanner(config: GarakConfig): GarakScanner {
  return new GarakScanner(config);
}
