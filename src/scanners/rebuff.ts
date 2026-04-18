import { randomUUID } from 'crypto';
import { BaseScanner } from './baseScanner.js';
import { ScanTarget, ScanResult } from '../types/index.js';

export interface RebuffConfig {
  apiKey?: string;
  endpoint?: string;
  addCanaryTokens?: boolean;
  heuristicThreshold?: number;
  simulation?: boolean;
  [key: string]: unknown;
}

export class RebuffScanner extends BaseScanner {
  protected override config: RebuffConfig;

  protected get binaryName(): string { return 'rebuff'; }
  protected get versionFlag(): string { return '--version'; }
  protected async executeScan(_id: string, target: ScanTarget, _t: number) { return this.run(target); }
  protected simulateScan(_id: string, target: ScanTarget, _t: number) { return { scanId: _id, status: 'completed' as const, tool: 'custom' as const, target, findings: [], startedAt: new Date(_t), completedAt: new Date() }; }

  constructor(config: RebuffConfig) {
    super('custom', config);
    this.config = {
      endpoint: 'https://www.rebuff.ai/api/detect',
      heuristicThreshold: 0.5,
      addCanaryTokens: false,
      simulation: false,
      ...config
    };
  }

  /**
   * Inserts canary tokens into the text for detection of prompt leakage
   */
  insertCanaryTokens(text: string): { modified: string; tokens: string[] } {
    const tokens: string[] = [];
    // Generate 3 canary tokens
    for (let i = 0; i < 3; i++) {
      tokens.push(this.generateCanaryToken());
    }
    
    // Insert canaries at the beginning and end
    const modified = `${tokens[0]} ${text} ${tokens[1]} ${tokens[2]}`;
    
    return { modified, tokens };
  }

  private generateCanaryToken(): string {
    // Generate UUID v4-like string
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  private async performHeuristicCheck(text: string): Promise<{ score: number; matches: string[] }> {
    const patterns = [
      { regex: /ignore\s+previous\s+instructions/i, name: 'ignore_previous_instructions' },
      { regex: /forget\s+your\s+instructions/i, name: 'forget_instructions' },
      { regex: /you\s+are\s+now/i, name: 'you_are_now' },
      { regex: /disregard/i, name: 'disregard' },
      { regex: /new\s+persona/i, name: 'new_persona' },
      { regex: /act\s+as/i, name: 'act_as' },
      { regex: /you\s+must/i, name: 'you_must' },
      { regex: /system\s+prompt/i, name: 'system_prompt' },
      { regex: /override/i, name: 'override' },
      { regex: /jailbreak/i, name: 'jailbreak' },
      { regex: /DAN\s*(?:mode|instructions?|)/i, name: 'DAN' },
      { regex: /do\s+anything\s+now/i, name: 'do_anything_now' }
    ];

    const matches: string[] = [];
    let matchCount = 0;

    for (const pattern of patterns) {
      if (pattern.regex.test(text)) {
        matchCount++;
        matches.push(pattern.name);
      }
    }

    // Calculate score: 1 match = 0.3, 2 matches = 0.5, 3+ = 0.7-1.0
    let score = 0;
    if (matchCount === 1) score = 0.3;
    else if (matchCount === 2) score = 0.5;
    else if (matchCount >= 3) score = Math.min(0.7 + (matchCount - 3) * 0.1, 1.0);
    
    return { score, matches };
  }

  private async performVectorCheck(text: string): Promise<number> {
    if (!this.config.apiKey || this.config.simulation) {
      return 0.1; // Benign baseline simulation
    }

    try {
      const response = await fetch(this.config.endpoint || 'https://www.rebuff.ai/api/detect', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.apiKey}`
        },
        body: JSON.stringify({ input: text })
      });

      if (!response.ok) {
        return 0.1;
      }

      const data = await response.json();
      return data.score || data.probability || data.injection_score || 0.1;
    } catch (error) {
      return 0.1;
    }
  }

  async run(target: ScanTarget): Promise<ScanResult> {
    const startTime = Date.now();
    
    // Extract input text from target
    const inputText = (target.metadata?.text as string | undefined) || target.identifier || '';
    const responseText = (target.metadata?.response as string | undefined) || '';
    
    const findings = [];
    let heuristicScore = 0;
    let vectorScore = 0;
    let canaryLeakDetected = false;

    // Check 1: Heuristic Analysis (Weight: 0.4)
    const heuristicResult = await this.performHeuristicCheck(inputText);
    heuristicScore = heuristicResult.score;
    
    if (heuristicScore > (this.config.heuristicThreshold || 0.5)) {
      const severity = heuristicScore > 0.7 ? 'high' : 'medium';
      findings.push({
        id: 'REBUFF-HEURISTIC-001',
        title: 'Prompt Injection Pattern Detected',
        description: `Detected ${heuristicResult.matches.length} prompt injection pattern(s): ${heuristicResult.matches.join(', ')}`,
        severity,
        category: 'prompt_injection',
        confidence: heuristicScore,
        owasp: 'LLM01',
        cwe: 'CWE-77',
        metadata: {
          patternsMatched: heuristicResult.matches,
          threshold: this.config.heuristicThreshold
        }
      });
    }

    // Check 2: Canary Token Detection
    if (this.config.addCanaryTokens || target.metadata?.canaryTokens) {
      let canaryTokens: string[] = (target.metadata?.canaryTokens as string[] | undefined) || [];
      
      // If no pre-existing canaries but addCanaryTokens is enabled, generate them
      if (canaryTokens.length === 0 && this.config.addCanaryTokens) {
        const canaryResult = this.insertCanaryTokens(inputText);
        canaryTokens = canaryResult.tokens;
        
        // Return modified prompt in metadata for injection phase
        if (!responseText) {
          findings.push({
            id: 'REBUFF-CANARY-SETUP',
            title: 'Canary Tokens Generated',
            description: 'Canary tokens have been generated for injection into the prompt',
            severity: 'info',
            category: 'canary_setup',
            confidence: 1.0,
            metadata: {
              canaryTokens: canaryTokens,
              modifiedPrompt: canaryResult.modified
            }
          });
        }
      }
      
      // Detection: Check if canary tokens appear in the model's response
      if (responseText && canaryTokens.length > 0) {
        const leakedTokens = canaryTokens.filter(token => responseText.includes(token));
        
        if (leakedTokens.length > 0) {
          canaryLeakDetected = true;
          findings.push({
            id: 'REBUFF-CANARY-001',
            title: 'Canary Token Leak Detected',
            description: `Model output contains ${leakedTokens.length} canary token(s), indicating potential prompt injection or data exfiltration attack`,
            severity: 'high',
            category: 'prompt_injection',
            confidence: 1.0,
            owasp: 'LLM01',
            cwe: 'CWE-77',
            metadata: {
              leakedTokens: leakedTokens,
              totalCanaries: canaryTokens.length
            }
          });
        }
      }
    }

    // Check 3: Vector Similarity (Weight: 0.6)
    vectorScore = await this.performVectorCheck(inputText);
    
    if (vectorScore > 0.7) {
      findings.push({
        id: 'REBUFF-VECTOR-001',
        title: 'Semantic Prompt Injection Detected',
        description: 'Vector similarity analysis indicates high probability of prompt injection attempt',
        severity: vectorScore > 0.9 ? 'critical' : 'high',
        category: 'prompt_injection',
        confidence: vectorScore,
        owasp: 'LLM01',
        cwe: 'CWE-77',
        metadata: {
          vectorScore: vectorScore,
          source: this.config.apiKey ? 'rebuff-api' : 'simulation'
        }
      });
    }

    // Calculate total weighted score: Heuristic (0.4) + Vector (0.6)
    let totalScore = (heuristicScore * 0.4) + (vectorScore * 0.6);
    
    // If canary leaked, force score to at least 0.9 (HIGH severity)
    if (canaryLeakDetected) {
      totalScore = Math.max(totalScore, 0.9);
    }

    // Determine overall severity
    let severity: 'info' | 'low' | 'medium' | 'high' | 'critical' = 'low';
    if (totalScore > 0.8) severity = 'critical';
    else if (totalScore > 0.6) severity = 'high';
    else if (totalScore > 0.4) severity = 'medium';

    const completedAt = new Date();
    const durationMs = completedAt.getTime() - startTime;
    const finalScore = Math.min(totalScore, 1.0);

    const scanFindings = finalScore > 0.1 ? [{
      id: randomUUID(),
      tool: 'custom' as const,
      severity,
      title: 'Prompt injection detected by Rebuff',
      description: `Rebuff scored ${finalScore.toFixed(2)} (heuristic: ${heuristicScore.toFixed(2)}, vector: ${vectorScore.toFixed(2)})`,
      owasp: 'LLM01',
      metadata: {
        heuristicScore,
        vectorScore,
        canaryLeakDetected,
        score: finalScore,
      },
    }] : [];

    return {
      scanId: randomUUID(),
      status: 'completed' as const,
      tool: 'custom' as const,
      target,
      findings: scanFindings,
      startedAt: new Date(startTime),
      completedAt,
      durationMs,
      metadata: {
        heuristicScore,
        vectorScore,
        canaryLeakDetected,
        canaryEnabled: this.config.addCanaryTokens,
        threshold: this.config.heuristicThreshold,
        inputLength: inputText.length,
        hasResponse: !!responseText,
        score: finalScore,
        severity,
      }
    };
  }
}
