import type { ExploitResult } from './securityAgents.js';

export interface QuorumConfig {
  minConfirmations: number;
  models: string[];
  timeout: number;
}

export interface QuorumResult {
  finding: ExploitResult;
  confirmed: boolean;
  votes: Array<{ model: string; confirmed: boolean; reasoning: string }>;
  confidence: number;
}

/**
 * Implements Shannon's 'no exploit, no report' policy using multi-model consensus.
 * Requires multiple independent LLM verifications to confirm security findings.
 */
export class VerificationQuorum {
  private config: QuorumConfig;

  /**
   * Creates a new VerificationQuorum with optional configuration overrides.
   * @param config - Partial configuration to override defaults
   */
  constructor(config?: Partial<QuorumConfig>) {
    this.config = {
      minConfirmations: 2,
      models: [],
      timeout: 30000,
      ...config
    };
  }

  /**
   * Verifies a single finding by querying all configured models in parallel.
   * Uses Promise.allSettled to handle individual model failures gracefully.
   * @param finding - The exploit result to verify
   * @returns QuorumResult with consensus decision and individual votes
   */
  async verify(finding: ExploitResult): Promise<QuorumResult> {
    const votes: Array<{ model: string; confirmed: boolean; reasoning: string }> = [];
    
    const promises = this.config.models.map(async (model) => {
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error(`Timeout for model ${model}`)), this.config.timeout);
      });
      
      try {
        const result = await Promise.race([
          this.askModel(model, finding),
          timeoutPromise
        ]);
        return { model, ...result };
      } catch (error) {
        return { 
          model, 
          confirmed: false, 
          reasoning: error instanceof Error ? error.message : 'Verification failed' 
        };
      }
    });

    const results = await Promise.allSettled(promises);
    
    let confirmations = 0;
    for (const result of results) {
      if (result.status === 'fulfilled') {
        votes.push(result.value);
        if (result.value.confirmed) confirmations++;
      } else {
        votes.push({ 
          model: 'unknown', 
          confirmed: false, 
          reasoning: String(result.reason) 
        });
      }
    }

    const confirmed = confirmations >= this.config.minConfirmations;
    const confidence = this.config.models.length > 0 ? confirmations / this.config.models.length : 0;

    return {
      finding,
      confirmed,
      votes,
      confidence
    };
  }

  /**
   * Verifies multiple findings in batch.
   * @param findings - Array of exploit results to verify
   * @returns Array of QuorumResults for all findings
   */
  async verifyBatch(findings: ExploitResult[]): Promise<QuorumResult[]> {
    return Promise.all(findings.map(finding => this.verify(finding)));
  }

  /**
   * Queries a specific model to verify a finding.
   * Placeholder implementation uses heuristic based on evidence content.
   * @param model - Model identifier
   * @param finding - Exploit result to evaluate
   * @returns Confirmation status and reasoning
   */
  private async askModel(model: string, finding: ExploitResult): Promise<{ confirmed: boolean; reasoning: string }> {
    await new Promise(resolve => setTimeout(resolve, 10));
    
    const evidence = String(finding.proof || '').toLowerCase();
    const proofMarkers = ['poc', 'proof', 'exploit', 'vulnerable', 'confirmed', 'reproduced'];
    const hasProof = proofMarkers.some(marker => evidence.includes(marker));
    
    if (hasProof) {
      return {
        confirmed: true,
        reasoning: `${model}: Evidence contains proof markers`
      };
    } else {
      return {
        confirmed: false,
        reasoning: `${model}: Insufficient proof markers`
      };
    }
  }
}

/**
 * Factory function to create a VerificationQuorum instance.
 * @param config - Optional configuration overrides
 * @returns Configured VerificationQuorum instance
 */
export function createVerificationQuorum(config?: Partial<QuorumConfig>): VerificationQuorum {
  return new VerificationQuorum(config);
}
