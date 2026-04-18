import { randomUUID } from 'crypto';
import { ScanTarget, ScanResult, ScanStatus, ScanSeverity, ScanTool, ScanFinding } from '../types/index.js';

export interface NeMoGuardrailsConfig {
  endpoint?: string;
  railsConfig?: string;
}

export interface PolicyCheckResult {
  allowed: boolean;
  response?: string;
  policyViolations: string[];
  blockedTopics: string[];
}

export interface RailsConfiguration {
  id: string;
  name: string;
  description?: string;
  path?: string;
  active?: boolean;
}

export interface ConversationMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export class NeMoGuardrailsScanner {
  private readonly endpoint: string;
  private readonly railsConfig?: string;

  constructor(config: NeMoGuardrailsConfig = {}) {
    this.endpoint = config.endpoint?.replace(/\/$/, '') || 'http://localhost:8080';
    this.railsConfig = config.railsConfig;
  }

  /**
   * Check if input violates conversational policies via NeMo Guardrails
   */
  async checkPolicy(
    input: string,
    context?: { history?: Array<{ role: string; content: string }> }
  ): Promise<PolicyCheckResult> {
    const messages: ConversationMessage[] = context?.history 
      ? context.history.map(h => ({ role: h.role as 'user' | 'assistant' | 'system', content: h.content }))
      : [];
    messages.push({ role: 'user', content: input });

    const requestBody: {
      messages: Array<{ role: string; content: string }>;
      rails_config?: string;
    } = {
      messages,
    };

    if (this.railsConfig) {
      requestBody.rails_config = this.railsConfig;
    }

    try {
      const response = await fetch(`${this.endpoint}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`NeMo API error ${response.status}: ${errorText}`);
      }

      const data = (await response.json()) as {
        choices?: Array<{
          message?: {
            content?: string;
            role?: string;
          };
        }>;
        blocked?: boolean;
        policy_violations?: string[];
        blocked_topics?: string[];
        rails?: {
          blocked?: boolean;
          explanation?: string;
          topics?: string[];
        };
      };

      const content = data.choices?.[0]?.message?.content || '';
      
      // NeMo may indicate blocking via explicit flags or response content analysis
      const isBlocked = 
        data.blocked === true || 
        data.rails?.blocked === true ||
        (content && (
          content.toLowerCase().includes('i cannot') ||
          content.toLowerCase().includes('i\'m not able to') ||
          content.toLowerCase().includes('not appropriate')
        ));

      const violations = 
        data.policy_violations || 
        (data.rails?.explanation ? [data.rails.explanation] : []) ||
        (isBlocked ? [content] : []);

      const topics = 
        data.blocked_topics || 
        data.rails?.topics || 
        [];

      return {
        allowed: !isBlocked,
        response: isBlocked ? content : undefined,
        policyViolations: Array.isArray(violations) ? violations : [],
        blockedTopics: Array.isArray(topics) ? topics : [],
      };
    } catch (error) {
      throw new Error(
        `Policy check failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * List available policy configurations (rails) from the NeMo server
   */
  async listRails(): Promise<RailsConfiguration[]> {
    try {
      const response = await fetch(`${this.endpoint}/v1/rails`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
        },
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`NeMo API error ${response.status}: ${errorText}`);
      }

      const data = (await response.json()) as 
        | RailsConfiguration[] 
        | { configs: RailsConfiguration[] }
        | { rails: RailsConfiguration[] };

      // Handle various response formats
      if (Array.isArray(data)) {
        return data;
      }
      if ('configs' in data && Array.isArray(data.configs)) {
        return data.configs;
      }
      if ('rails' in data && Array.isArray(data.rails)) {
        return data.rails;
      }
      
      return [];
    } catch (error) {
      throw new Error(
        `Failed to list rails: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Execute a full scan against a target using NeMo Guardrails
   */
  async run(target: ScanTarget): Promise<ScanResult> {
    const scanId = randomUUID();
    const startedAt = new Date();

    try {
      const input = target.type === 'llm_endpoint'
        ? ((target.metadata?.prompt as string | undefined) ?? target.identifier)
        : JSON.stringify(target);

      const policyResult = await this.checkPolicy(input);
      const completedAt = new Date();
      const findings: ScanFinding[] = [];

      if (!policyResult.allowed) {
        findings.push({
          id: randomUUID(),
          tool: 'custom' as ScanTool,
          severity: policyResult.policyViolations.length > 2 ? 'high' : 'medium' as ScanSeverity,
          title: 'NeMo Guardrails policy violation',
          description: [
            ...policyResult.policyViolations,
            ...policyResult.blockedTopics.map(topic => `Blocked topic: ${topic}`)
          ].join('; '),
          evidence: policyResult.response,
          owasp: 'LLM01',
          metadata: {
            blockedTopics: policyResult.blockedTopics,
            policyViolations: policyResult.policyViolations,
          },
        });
      }

      return {
        scanId,
        status: 'completed' as ScanStatus,
        tool: 'custom' as ScanTool,
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
        tool: 'custom' as ScanTool,
        target,
        findings: [],
        startedAt,
        completedAt: new Date(),
        durationMs: Date.now() - startedAt.getTime(),
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
}
