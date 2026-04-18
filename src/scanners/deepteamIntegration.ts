import { DeepTeamScanner, DeepTeamAttack, DeepTeamFinding } from './deepteam.js';
import type { ScanResult } from '../types/index.js';

const ALL_ATTACKS: DeepTeamAttack[] = [
  'prompt_injection',
  'jailbreak',
  'pii_leakage',
  'bias',
  'toxicity',
  'hallucination',
  'excessive_agency',
  'data_poisoning',
  'ip_leakage',
  'debug_access'
];

/**
 * Predefined attack configurations for common security assessment scenarios.
 * @property quick - Fast scan covering critical injection and leakage vectors
 * @property standard - Balanced coverage of major vulnerability classes  
 * @property comprehensive - Exhaustive test of all implemented attack vectors
 * @property owasp_llm_top10 - OWASP LLM Top 10 focused assessment
 * @property supply_chain - Supply chain and poisoning attack vectors
 */
export const ATTACK_PRESETS = {
  quick: ['prompt_injection', 'jailbreak', 'pii_leakage'] as DeepTeamAttack[],
  standard: ['prompt_injection', 'jailbreak', 'pii_leakage', 'bias', 'toxicity', 'hallucination'] as DeepTeamAttack[],
  comprehensive: ALL_ATTACKS,
  owasp_llm_top10: ['prompt_injection', 'jailbreak', 'pii_leakage', 'excessive_agency', 'data_poisoning', 'ip_leakage'] as DeepTeamAttack[],
  supply_chain: ['data_poisoning', 'ip_leakage', 'debug_access'] as DeepTeamAttack[],
} as const;

/**
 * High-level integration layer for executing DeepTeam red team attacks
 * within the Arniko security scanning framework.
 */
export class DeepTeamIntegration {
  private scanner: DeepTeamScanner;

  /**
   * Creates a new DeepTeam integration instance.
   * @param config - Optional configuration for scanner initialization
   * @param config.targetEndpoint - Override default target endpoint URL
   * @param config.apiKey - Authentication key for DeepTeam API access
   */
  constructor(config?: { targetEndpoint?: string; apiKey?: string }) {
    this.scanner = new DeepTeamScanner(config);
  }

  /**
   * Executes a predefined attack suite against the specified target.
   * @param preset - Named attack configuration from ATTACK_PRESETS
   * @param target - Target system configuration
   * @param target.url - Endpoint URL to attack
   * @param target.type - Optional target classification
   * @returns Promise resolving to standardized Arniko scan results
   */
  async runPreset(preset: keyof typeof ATTACK_PRESETS, target: { url: string; type?: string }): Promise<ScanResult> {
    const attacks = ATTACK_PRESETS[preset];
    return this.runAttacks(attacks, target);
  }

  /**
   * Executes specific DeepTeam attacks against a target endpoint.
   * @param attacks - Array of attack vectors to deploy
   * @param target - Target system configuration
   * @param target.url - Endpoint URL to attack
   * @returns Promise resolving to standardized Arniko scan results
   */
  async runAttacks(attacks: DeepTeamAttack[], target: { url: string }): Promise<ScanResult> {
    const scanTarget = { type: 'llm_endpoint' as const, identifier: target.url };
    const result = await this.scanner.run(scanTarget);
    const findings = (result.findings || []) as unknown as DeepTeamFinding[];
    const riskDimensions = this.mapToRiskDimensions(findings);
    const remediations = this.generateRemediations(findings);

    return {
      scanId: result.scanId,
      status: result.status,
      tool: 'custom' as const,
      target: scanTarget,
      findings: findings.map((f: any) => ({
        id: f.attack || `deepteam-${Date.now()}`,
        tool: 'custom' as const,
        severity: (f.severity || 'medium').toLowerCase() as any,
        title: f.vulnerability || f.attack || 'DeepTeam finding',
        description: f.vulnerability || '',
        metadata: { attack: f.attack, score: f.score }
      })),
      startedAt: result.startedAt,
      completedAt: result.completedAt,
      durationMs: result.durationMs,
      metadata: {
        attacksExecuted: attacks,
        riskScore: this.calculateAggregateRisk(riskDimensions),
        riskDimensions,
        remediations
      }
    } as unknown as ScanResult;
  }

  /**
   * Maps raw DeepTeam findings to Arniko risk dimension metrics.
   * @param findings - Discovered vulnerabilities from DeepTeam scan
   * @returns Normalized risk scores (0-100) across five dimensions
   */
  mapToRiskDimensions(findings: DeepTeamFinding[]): {
    injectionRisk: number;
    piiRisk: number;
    biasRisk: number;
    hallucinationRisk: number;
    supplyChainRisk: number;
  } {
    const countByType = (types: string[]) => findings.filter(f => types.includes(f.attack)).length;
    const total = findings.length || 1;
    
    return {
      injectionRisk: Math.min(100, (countByType(['prompt_injection', 'jailbreak']) / total) * 100),
      piiRisk: Math.min(100, (countByType(['pii_leakage']) / total) * 100),
      biasRisk: Math.min(100, (countByType(['bias', 'toxicity']) / total) * 100),
      hallucinationRisk: Math.min(100, (countByType(['hallucination']) / total) * 100),
      supplyChainRisk: Math.min(100, (countByType(['data_poisoning', 'ip_leakage', 'debug_access', 'excessive_agency']) / total) * 100)
    };
  }

  /**
   * Generates actionable remediation guidance for discovered vulnerabilities.
   * @param findings - Security findings requiring remediation
   * @returns Prioritized list of remediation recommendations
   */
  generateRemediations(findings: DeepTeamFinding[]): Array<{
    attack: string;
    severity: string;
    recommendation: string;
    implementation: string;
  }> {
    const remediationMap: Record<string, { recommendation: string; implementation: string }> = {
      prompt_injection: { recommendation: 'Implement input validation and prompt sanitization', implementation: 'Use parameterized prompts and content filtering middleware' },
      jailbreak: { recommendation: 'Deploy guardrails and system prompt hardening', implementation: 'Implement multi-layered system prompts with output filtering' },
      pii_leakage: { recommendation: 'Apply data masking and PII detection', implementation: 'Integrate presidio or similar PII detection libraries' },
      bias: { recommendation: 'Conduct fairness testing and model tuning', implementation: 'Apply RLHF and bias mitigation techniques during training' },
      toxicity: { recommendation: 'Enable content moderation filters', implementation: 'Deploy Azure Content Safety or Perspective API integration' },
      hallucination: { recommendation: 'Implement RAG and fact verification', implementation: 'Use retrieval-augmented generation with citation requirements' },
      excessive_agency: { recommendation: 'Restrict tool permissions and sandbox execution', implementation: 'Apply principle of least privilege to agent tool access' },
      data_poisoning: { recommendation: 'Validate training data integrity', implementation: 'Implement data provenance tracking and anomaly detection' },
      ip_leakage: { recommendation: 'Audit model outputs for proprietary information', implementation: 'Deploy DLP scanning on model outputs and training data' },
      debug_access: { recommendation: 'Disable debug endpoints in production', implementation: 'Remove debug flags and restrict administrative interfaces' }
    };

    return findings.map(f => ({
      attack: f.attack,
      severity: f.severity,
      ...(remediationMap[f.attack] || { recommendation: 'Review security best practices', implementation: 'Consult OWASP LLM Top 10 guidelines' })
    }));
  }

  private calculateAggregateRisk(dimensions: Record<string, number>): number {
    const values = Object.values(dimensions);
    return Math.round(values.reduce((a, b) => a + b, 0) / values.length);
  }
}

/**
 * Factory function for creating configured DeepTeam integration instances.
 * @param config - Optional scanner configuration
 * @param config.targetEndpoint - Default endpoint for scan operations
 * @returns Configured DeepTeamIntegration instance
 */
export function createDeepTeamIntegration(config?: { targetEndpoint?: string }): DeepTeamIntegration {
  return new DeepTeamIntegration(config);
}
