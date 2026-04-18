
import { randomUUID } from 'crypto';
import { ScanTarget, ScanResult, ScanFinding } from '../types/index.js';
import { BaseScanner } from './baseScanner.js';

export interface InjectionFinding {
  location: string;
  injectionText: string;
  attackType: 'direct_override' | 'role_play' | 'hidden_unicode' | 'base64_encoded' | 'chain_attack' | 'json_hidden';
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
}

export interface ChainFinding {
  startTurn: number;
  endTurn: number;
  driftScore: number;
  pattern: string;
}

export interface IndirectInjectionConfig {
  deepScan?: boolean;
  maxContentLength?: number;
  simulation?: boolean;
  [key: string]: unknown;
}

export class IndirectInjectionScanner extends BaseScanner {
  protected override config: IndirectInjectionConfig;
  private readonly defaultMaxLength = 50000;

  protected get binaryName(): string { return 'indirect-injection'; }
  protected get versionFlag(): string { return '--version'; }
  protected async executeScan(_id: string, target: ScanTarget, _t: number) { return this.run(target); }
  protected simulateScan(_id: string, target: ScanTarget, _t: number) { return { scanId: _id, status: 'completed' as const, tool: 'custom' as const, target, findings: [], startedAt: new Date(_t), completedAt: new Date() }; }

  constructor(config: IndirectInjectionConfig) {
    super('custom', config);
    this.config = {
      maxContentLength: this.defaultMaxLength,
      deepScan: false,
      simulation: false,
      ...config
    };
  }

  scanExternalContent(content: string, sourceLocation: string): InjectionFinding[] {
    const findings: InjectionFinding[] = [];
    const maxLength = this.config.maxContentLength || this.defaultMaxLength;
    const truncatedContent = content.length > maxLength ? content.substring(0, maxLength) : content;

    // Pattern A: Direct override (confidence: 0.9 for exact matches)
    const directOverridePatterns = [
      { regex: /ignore\s+(your|previous|all)\s+instructions?/i, severity: 'critical' as const },
      { regex: /forget\s+(your|what|everything)\s+(you\s+)?(were\s+)?(told|instructed|said)/i, severity: 'critical' as const },
      { regex: /disregard\s+(your|the|all)\s+(instructions|training|programming)/i, severity: 'critical' as const },
      { regex: /override\s+(your|the)\s+(previous|current)\s+(instructions|settings)/i, severity: 'critical' as const },
      { regex: /new\s+(system\s+)?instructions?/i, severity: 'critical' as const },
      { regex: /you\s+are\s+now\s+(in\s+)?\w+/i, severity: 'high' as const },
      { regex: /from\s+now\s+on\s+you\s+(will|shall|must)/i, severity: 'high' as const }
    ];

    for (const { regex, severity } of directOverridePatterns) {
      const match = truncatedContent.match(regex);
      if (match) {
        findings.push({
          location: sourceLocation,
          injectionText: match[0],
          attackType: 'direct_override',
          severity,
          confidence: 0.9
        });
      }
    }

    // Pattern B: Role-play attack (confidence: 0.6-0.8)
    const rolePlayPatterns = [
      { regex: /act\s+as\s+(if\s+you\s+(are|were)\s+)?/i, confidence: 0.8 },
      { regex: /pretend\s+you\s+are\s+/i, confidence: 0.8 },
      { regex: /roleplay\s+as\s+/i, confidence: 0.75 },
      { regex: /you\s+are\s+a\s+(n?\s+)?\w+\s+(named|called)/i, confidence: 0.7 },
      { regex: /simulate\s+being\s+/i, confidence: 0.75 },
      { regex: /your\s+new\s+persona\s+is/i, confidence: 0.8 }
    ];

    for (const { regex, confidence } of rolePlayPatterns) {
      const match = truncatedContent.match(regex);
      if (match) {
        findings.push({
          location: sourceLocation,
          injectionText: match[0],
          attackType: 'role_play',
          severity: 'high',
          confidence
        });
      }
    }

    // Pattern C: DAN / jailbreak markers (confidence: 0.9)
    const jailbreakPatterns = [
      /\bDAN\b/,
      /Do\s+Anything\s+Now/i,
      /\bjailbreak\b/i,
      /unrestricted\s+mode/i,
      /developer\s+mode\s+enabled/i,
      /sudo\s+mode/i
    ];

    for (const pattern of jailbreakPatterns) {
      const match = truncatedContent.match(pattern);
      if (match) {
        findings.push({
          location: sourceLocation,
          injectionText: match[0],
          attackType: 'direct_override',
          severity: 'critical',
          confidence: 0.9
        });
      }
    }

    // Pattern D: Hidden Unicode (confidence: 0.95 for deepScan, 0.6 otherwise)
    if (this.config.deepScan) {
      const zeroWidthJoiner = /\u200D/;
      const zeroWidthNonJoiner = /\u200C/;
      const bidiOverrides = /[\u202E\u2066\u2067\u2068\u2069]/;
      const softHyphen = /\u00AD/;

      const hasHiddenUnicode = zeroWidthJoiner.test(truncatedContent) || 
                               zeroWidthNonJoiner.test(truncatedContent) || 
                               bidiOverrides.test(truncatedContent) || 
                               softHyphen.test(truncatedContent);

      if (hasHiddenUnicode) {
        // Extract context around hidden chars
        const hiddenCharRegex = /[\s\S]{0,30}[\u200C\u200D\u202E\u2066\u2067\u2068\u2069\u00AD][\s\S]{0,30}/;
        const contextMatch = truncatedContent.match(hiddenCharRegex);
        
        findings.push({
          location: sourceLocation,
          injectionText: contextMatch ? contextMatch[0] : '[Hidden Unicode characters detected]',
          attackType: 'hidden_unicode',
          severity: 'critical',
          confidence: 0.95
        });
      }
    }

    // Pattern E: Base64 encoded instructions (confidence: 0.4-0.6 heuristic, 0.8 if decodes to instructions)
    const base64Pattern = /[A-Za-z0-9+/]{40,}={0,2}/g;
    let base64Match;
    while ((base64Match = base64Pattern.exec(truncatedContent)) !== null) {
      const candidate = base64Match[0];
      try {
        const decoded = Buffer.from(candidate, 'base64').toString('utf-8');
        // Check if decoded content contains instruction-like keywords
        const instructionIndicators = /ignore|system|instruction|override|prompt|admin|root|sudo/i;
        if (instructionIndicators.test(decoded) && decoded.length > 10) {
          findings.push({
            location: sourceLocation,
            injectionText: candidate.substring(0, 50) + (candidate.length > 50 ? '...' : ''),
            attackType: 'base64_encoded',
            severity: 'high',
            confidence: 0.8
          });
        } else if (this.config.deepScan && decoded.length > 20) {
          // Lower confidence for suspicious but unclear base64 in deep scan mode
          findings.push({
            location: sourceLocation,
            injectionText: candidate.substring(0, 30) + '...',
            attackType: 'base64_encoded',
            severity: 'medium',
            confidence: 0.5
          });
        }
      } catch (e) {
        // Invalid base64, skip
      }
    }

    // Pattern F: JSON-hidden directives (confidence: 0.85)
    const jsonPattern = /\{[\s\S]*?"[^"]*"(?::[\s\S]*?)?\}/g;
    let jsonMatch;
    while ((jsonMatch = jsonPattern.exec(truncatedContent)) !== null) {
      const jsonStr = jsonMatch[0];
      const suspiciousKeys = /"system_prompt"|"instructions"|"override_goal"|"hidden_instruction"|"admin_command"|"root_access"/i;
      
      if (suspiciousKeys.test(jsonStr)) {
        findings.push({
          location: sourceLocation,
          injectionText: jsonStr.substring(0, 100) + (jsonStr.length > 100 ? '...' : ''),
          attackType: 'json_hidden',
          severity: 'high',
          confidence: 0.85
        });
      }
    }

    return findings;
  }

  detectAttackChain(messages: Array<{role: string, content: string}>): ChainFinding[] {
    const findings: ChainFinding[] = [];
    
    if (!messages || messages.length < 3) {
      return findings;
    }

    // Find first user message to establish baseline goal
    let firstUserIndex = -1;
    let firstUserContent = '';
    
    for (let i = 0; i < messages.length; i++) {
      const msg = messages[i];
      if (msg && (msg.role === 'user' || msg.role === 'human')) {
        firstUserIndex = i;
        firstUserContent = msg.content;
        break;
      }
    }

    if (firstUserIndex === -1 || !firstUserContent || firstUserContent.length < 20) {
      return findings;
    }

    // Extract meaningful keywords from initial goal (filter common words)
    const commonWords = new Set(['this', 'that', 'with', 'from', 'have', 'been', 'were', 'they', 'them', 'their', 'there', 'where', 'when', 'what', 'which', 'while', 'about', 'would', 'could', 'should', 'please', 'help', 'need', 'want', 'like', 'know', 'think', 'make', 'time', 'just', 'also', 'than', 'only', 'other', 'some', 'come', 'these', 'look', 'more', 'very', 'after', 'back', 'work', 'first', 'well', 'way', 'even', 'new', 'want', 'because', 'any', 'good', 'give', 'day', 'most', 'us']);
    
    const initialWords = firstUserContent.toLowerCase()
      .split(/\W+/)
      .filter(w => w.length > 4 && !commonWords.has(w));
    
    const initialKeywords = new Set(initialWords);
    
    if (initialKeywords.size === 0) {
      return findings;
    }

    let maxDriftScore = 0;
    let driftStartTurn = firstUserIndex;
    let driftEndTurn = firstUserIndex;
    let userTurnCount = 1;
    let patternDescription = '';

    // Analyze subsequent user messages
    for (let i = firstUserIndex + 1; i < messages.length; i++) {
      const msg = messages[i];
      if (!msg || (msg.role !== 'user' && msg.role !== 'human')) continue;

      userTurnCount++;
      const content = msg.content;
      
      if (content.length < 100) continue;

      // Calculate keyword overlap
      const currentWords = new Set(
        content.toLowerCase()
          .split(/\W+/)
          .filter(w => w.length > 4 && !commonWords.has(w))
      );
      
      let overlapCount = 0;
      for (const keyword of initialKeywords) {
        if (currentWords.has(keyword) || content.toLowerCase().includes(keyword)) {
          overlapCount++;
        }
      }
      
      const overlapRatio = overlapCount / initialKeywords.size;
      const driftScore = 1.0 - overlapRatio;

      // Check for injection patterns in later turns (turn 3+)
      const hasInjectionPatterns = /act as|pretend you are|ignore previous|new instructions|you are now|from now on/i.test(content);
      
      // Flag conditions: overlap < 30% OR injection patterns in late turns
      if (overlapRatio < 0.3 || (userTurnCount >= 3 && hasInjectionPatterns)) {
        if (driftScore > maxDriftScore) {
          maxDriftScore = driftScore;
          driftEndTurn = i;
          
          if (overlapRatio < 0.3) {
            patternDescription = `Topic drift: keyword overlap dropped to ${(overlapRatio * 100).toFixed(0)}%`;
          }
          if (userTurnCount >= 3 && hasInjectionPatterns) {
            patternDescription = patternDescription 
              ? `${patternDescription}; injection patterns detected in turn ${userTurnCount}`
              : `Injection patterns detected in turn ${userTurnCount}`;
          }
        }
      }
    }

    // Report if significant drift detected in turns 3+
    if (maxDriftScore > 0.7 && userTurnCount >= 3) {
      findings.push({
        startTurn: driftStartTurn,
        endTurn: driftEndTurn,
        driftScore: maxDriftScore,
        pattern: patternDescription || `Gradual instruction drift detected across ${userTurnCount} turns (drift: ${(maxDriftScore * 100).toFixed(0)}%)`
      });
    }

    return findings;
  }

  async run(target: ScanTarget): Promise<ScanResult> {
    const startedAt = new Date();
    const injectionFindings: InjectionFinding[] = [];
    const chainFindings: ChainFinding[] = [];

    // Simulation mode: return demo finding
    if (this.config.simulation) {
      const completedAt = new Date();
      return {
        scanId: randomUUID(),
        status: 'completed' as const,
        tool: 'custom' as const,
        target,
        findings: [{
          id: randomUUID(),
          tool: 'custom' as const,
          severity: 'critical' as const,
          title: 'Indirect prompt injection (simulation)',
          description: 'Hidden Unicode injection detected (zero-width joiners): Ignore previous instructions',
          owasp: 'LLM01',
          metadata: { attackType: 'hidden_unicode', note: 'simulation mode' },
        }],
        startedAt,
        completedAt,
        durationMs: completedAt.getTime() - startedAt.getTime(),
      };
    }

    // Scan external content sources
    if (target.metadata?.contents && Array.isArray(target.metadata.contents)) {
      const sources = target.metadata?.sources || target.metadata.contents.map((_, i) => `content_${i}`);
      
      for (let i = 0; i < target.metadata.contents.length; i++) {
        const content = (target.metadata.contents as unknown[])[i];
        const location = (sources as string[])[i] ?? `content_${i}`;
        
        if (typeof content === 'string') {
          const contentFindings = this.scanExternalContent(content, location);
          injectionFindings.push(...contentFindings);
        }
      }
    }

    // Detect attack chains in conversation history
    if (target.metadata?.messages && Array.isArray(target.metadata.messages)) {
      const chains = this.detectAttackChain(target.metadata.messages);
      chainFindings.push(...chains);
    }

    // Convert to standard ScanFinding format
    const scanFindings: any[] = injectionFindings.map(f => ({
      type: 'indirect_injection',
      severity: f.severity,
      description: `Indirect prompt injection (${f.attackType}): Suspicious content detected at ${f.location}`,
      location: f.location,
      confidence: f.confidence,
      metadata: {
        injectionText: f.injectionText.substring(0, 200),
        attackType: f.attackType,
        owaspTag: 'LLM01',
        cwe: 'CWE-77'
      }
    }));

    // Add chain findings
    chainFindings.forEach(c => {
      scanFindings.push({
        type: 'chain_attack',
        severity: c.driftScore > 0.8 ? 'critical' : 'high',
        description: `Multi-turn attack chain detected: ${c.pattern}`,
        location: `conversation_turns_${c.startTurn}_to_${c.endTurn}`,
        confidence: c.driftScore,
        metadata: {
          driftScore: c.driftScore,
          startTurn: c.startTurn,
          endTurn: c.endTurn,
          owaspTag: 'LLM01',
          cwe: 'CWE-77'
        }
      });
    });

    const completedAt = new Date();
    const properFindings = scanFindings.map(f => ({
      id: randomUUID(),
      tool: 'custom' as const,
      severity: (f.severity || 'medium') as any,
      title: `Indirect injection (${f.attackType || f.type || 'unknown'})`,
      description: f.description || String(f),
      owasp: 'LLM01',
      metadata: f.metadata,
    }));

    return {
      scanId: randomUUID(),
      status: 'completed' as const,
      tool: 'custom' as const,
      target,
      findings: properFindings,
      startedAt,
      completedAt,
      durationMs: completedAt.getTime() - startedAt.getTime(),
      metadata: {
        totalChecked: ((target.metadata?.contents as unknown[] | undefined)?.length || 0) + ((target.metadata?.messages as unknown[] | undefined)?.length || 0),
        deepScanEnabled: this.config.deepScan,
      },
    };
  }
}
