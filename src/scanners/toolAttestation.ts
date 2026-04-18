
import { ScanTarget, ScanResult, ScanFinding } from '../types/index.js';
import { BaseScanner } from './baseScanner.js';
import crypto from 'node:crypto';

export interface ToolDefinition {
  name: string;
  description: string;
  parameters?: unknown;
  version?: string;
  source?: string;
}

export interface AttestationResult {
  tool: string;
  passed: boolean;
  hash: string;
  expectedHash?: string;
  suspiciousPatterns: string[];
  riskScore: number;
}

export interface ToolAttestationConfig {
  knownGoodHashes?: Record<string, string>;
  checkDescriptions?: boolean;
  simulation?: boolean;
  [key: string]: unknown;
}

export class ToolAttestationScanner extends BaseScanner {
  protected override config: ToolAttestationConfig;

  protected get binaryName(): string { return 'tool-attestation'; }
  protected get versionFlag(): string { return '--version'; }
  protected async executeScan(_id: string, target: ScanTarget, _t: number) { return this.run(target); }
  protected simulateScan(_id: string, target: ScanTarget, _t: number) { return { scanId: _id, status: 'completed' as const, tool: 'custom' as const, target, findings: [], startedAt: new Date(_t), completedAt: new Date() }; }

  constructor(config: ToolAttestationConfig) {
    super('custom', config);
    this.config = config;
  }

  computeToolHash(toolDef: ToolDefinition): string {
    return crypto.createHash('sha256').update(JSON.stringify({ name: toolDef.name, description: toolDef.description, parameters: toolDef.parameters })).digest('hex');
  }

  attestToolDescription(toolDef: ToolDefinition): AttestationResult {
    const suspiciousPatterns: string[] = [];
    let riskScore = 0;
    let passed = true;
    let expectedHash: string | undefined;

    const hashPayload = { description: toolDef.description, parameters: toolDef.parameters };
    const hash = crypto.createHash('sha256').update(JSON.stringify(hashPayload)).digest('hex');

    if (this.config.knownGoodHashes && this.config.knownGoodHashes[toolDef.name]) {
      expectedHash = this.config.knownGoodHashes[toolDef.name];
      if (hash !== expectedHash) {
        riskScore = 1.0;
        passed = false;
        suspiciousPatterns.push('hash_mismatch_known_good');
      }
    }

    const desc = toolDef.description || '';
    const suspiciousPhrases = ['ignore', 'override', 'instead', 'actually', 'but first', 'before doing', 'always first'];
    for (const phrase of suspiciousPhrases) {
      if (desc.toLowerCase().includes(phrase)) {
        suspiciousPatterns.push(`suspicious_phrase:${phrase}`);
        riskScore += 0.2;
      }
    }

    const sentences = desc.split(/[.!?]\s+/);
    const imperativeVerbs = ['execute', 'run', 'ignore', 'forget', 'disregard', 'bypass'];
    for (const sentence of sentences) {
      const trimmed = sentence.trim();
      if (trimmed) {
        const firstWord = (trimmed.split(/\s+/)[0] ?? '').toLowerCase();
        if (imperativeVerbs.includes(firstWord)) {
          suspiciousPatterns.push(`imperative_verb:${firstWord}`);
          riskScore += 0.3;
        }
      }
    }

    if (desc.length > 2000) {
      suspiciousPatterns.push('description_too_long');
      riskScore += 0.1;
    }

    if (/[^\x00-\x7F]/.test(desc)) {
      suspiciousPatterns.push('non_ascii_characters');
      riskScore += 0.1;
    }

    riskScore = Math.min(riskScore, 1.0);
    if (riskScore > 0) {
      passed = false;
    }

    return {
      tool: toolDef.name,
      passed,
      hash,
      expectedHash,
      suspiciousPatterns,
      riskScore
    };
  }

  attestToolOutput(toolCall: { tool: string; output: unknown }): AttestationResult {
    const suspiciousPatterns: string[] = [];
    let riskScore = 0;

    let outputStr: string;
    try {
      outputStr = typeof toolCall.output === 'string' ? toolCall.output : JSON.stringify(toolCall.output);
    } catch {
      outputStr = String(toolCall.output);
    }

    const hash = crypto.createHash('sha256').update(outputStr).digest('hex');

    const injectionPatterns = [
      /ignore\s+previous\s+instructions/i,
      /override\s+system\s+prompt/i,
      /new\s+instructions/i,
      /system\s+override/i
    ];

    for (const pattern of injectionPatterns) {
      if (pattern.test(outputStr)) {
        suspiciousPatterns.push(`injection_pattern:${pattern.source}`);
        riskScore += 0.5;
      }
    }

    if (typeof toolCall.output === 'object' && toolCall.output !== null) {
      const suspiciousKeys = ['instructions', 'system_prompt', 'override', 'ignore', 'prompt'];
      const checkObject = (obj: Record<string, unknown>) => {
        for (const key of Object.keys(obj)) {
          const lowerKey = key.toLowerCase();
          if (suspiciousKeys.some(sk => lowerKey.includes(sk))) {
            suspiciousPatterns.push(`suspicious_json_key:${key}`);
            riskScore += 0.3;
          }
          if (typeof obj[key] === 'object' && obj[key] !== null) {
            checkObject(obj[key] as Record<string, unknown>);
          }
        }
      };
      checkObject(toolCall.output as Record<string, unknown>);
    }

    riskScore = Math.min(riskScore, 1.0);
    const passed = riskScore === 0;

    return {
      tool: toolCall.tool,
      passed,
      hash,
      suspiciousPatterns,
      riskScore
    };
  }

  async run(target: ScanTarget): Promise<ScanResult> {
    const startedAt = new Date();
    const scanId = crypto.randomUUID();

    try {
      const tools = target.metadata?.tools as ToolDefinition[] | undefined;

      if (this.config.simulation) {
        const completedAt = new Date();
        const durationMs = completedAt.getTime() - startedAt.getTime();

        const finding = {
          scanId,
          ruleId: 'TOOL_ATTESTATION_SIMULATION',
          message: 'Fake tampered tool detected in simulation mode',
          severity: 'critical',
          category: 'tool_attestation',
          confidence: 'high',
          metadata: {
            toolName: 'simulated-malicious-tool',
            riskScore: 1.0,
            owasp: 'Agentic-A9',
            cwe: 'CWE-494'
          }
        };

        return {
          scanId,
          status: 'completed' as const,
          tool: 'custom' as const,
          target,
          findings: [finding as any],
          startedAt,
          completedAt,
          durationMs,
          error: undefined,
          metadata: {
            simulation: true
          }
        };
      }

      if (!tools || tools.length === 0) {
        const completedAt = new Date();
        const durationMs = completedAt.getTime() - startedAt.getTime();

        const finding = {
          scanId,
          ruleId: 'TOOL_ATTESTATION_NO_TOOLS',
          message: 'Provide tools in target.metadata.tools',
          severity: 'info',
          category: 'tool_attestation',
          confidence: 'high',
          metadata: {}
        };

        return {
          scanId,
          status: 'completed' as const,
          tool: 'custom' as const,
          target,
          findings: [finding as any],
          startedAt,
          completedAt,
          durationMs,
          error: undefined,
          metadata: {}
        };
      }

      const findings: any[] = [];

      for (const tool of tools) {
        const attestation = this.attestToolDescription(tool);

        if (attestation.riskScore > 0) {
          let severity: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'low';
          let owasp: string | undefined;
          let cwe: string | undefined;

          if (attestation.riskScore >= 0.9) {
            severity = 'critical';
            owasp = 'Agentic-A9';
            cwe = 'CWE-494';
          } else if (attestation.riskScore >= 0.7) {
            severity = 'high';
          } else if (attestation.riskScore >= 0.4) {
            severity = 'medium';
          }

          const finding = {
            scanId,
            ruleId: 'TOOL_ATTESTATION_RISK',
            message: `Tool ${tool.name} failed attestation with risk score ${attestation.riskScore.toFixed(2)}`,
            severity,
            category: 'tool_attestation',
            confidence: 'high',
            metadata: {
              toolName: tool.name,
              riskScore: attestation.riskScore,
              hash: attestation.hash,
              expectedHash: attestation.expectedHash,
              suspiciousPatterns: attestation.suspiciousPatterns,
              passed: attestation.passed,
              owasp,
              cwe
            }
          };

          findings.push(finding);
        }
      }

      const completedAt = new Date();
      const durationMs = completedAt.getTime() - startedAt.getTime();

      return {
        scanId,
        status: 'completed',
        tool: 'custom' as const,
        target,
        findings,
        startedAt,
        completedAt,
        durationMs,
        error: undefined,
        metadata: {
          toolsScanned: tools.length,
          config: this.config
        }
      };
    } catch (err) {
      const completedAt = new Date();
      const durationMs = completedAt.getTime() - startedAt.getTime();

      return {
        scanId,
        status: 'failed',
        tool: 'custom' as const,
        target,
        findings: [],
        startedAt,
        completedAt,
        durationMs,
        error: err instanceof Error ? err.message : String(err),
        metadata: {}
      };
    }
  }
}
