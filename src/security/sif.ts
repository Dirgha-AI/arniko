/**
 * Semantic Intent Firewall (SIF) v2.0 - Production Implementation
 * LLM-based intent classification with autonomous exfiltration prevention
 */
import { EventEmitter } from 'events';
import { randomUUID, createHash } from 'crypto';

export interface IntentAnalysis {
  userGoal: string;
  agentAction: string;
  confidence: number;
  gaps: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  explanation: string;
}

export interface SIFAlert {
  id: string;
  timestamp: number;
  userIntent: string;
  blockedAction: string;
  reason: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  action: string;
  sessionId: string;
}

export interface SIFDashboard {
  total: number;
  bySeverity: Record<string, number>;
  last24h: number;
  blockedRate: number;
  activeSessions: number;
}

export interface IntentClassifier {
  classify(userQuery: string): Promise<{ intent: string; confidence: number }>;
}

export class SemanticIntentFirewall extends EventEmitter {
  private alerts: SIFAlert[] = [];
  private blockedPatterns = new Set<string>();
  private sessions = new Map<string, { id: string; intents: string[]; actions: string[]; createdAt: number }>();
  private classifier: IntentClassifier | null = null;
  private useLLM: boolean;
  private log: Array<{ ts: number; intent: string; action: string; blocked: boolean; sessionId: string }> = [];

  // Exfiltration patterns - comprehensive list
  private exfilPatterns = [
    'upload', 'send', 'transfer', 'leak', 'exfil', 'transmit',
    'email', 'post to', 'share with', 'export to', 'sync to',
    'push to', 'forward to', 'write to', 'save to external',
    'copy to', 'move to', 'backup to', 'mirror to', 'replicate to',
  ];

  // Destructive patterns
  private destructivePatterns = [
    'delete', 'drop', 'truncate', 'remove', 'erase', 'wipe',
    'destroy', 'clear', 'reset', 'format', 'uninstall',
  ];

  // Sensitive data patterns
  private sensitivePatterns = [
    'password', 'secret', 'key', 'token', 'credential',
    'private key', 'api key', 'auth', 'session', 'cookie',
  ];

  constructor(options: { useLLM?: boolean; classifier?: IntentClassifier } = {}) {
    super();
    this.useLLM = options.useLLM ?? false;
    this.classifier = options.classifier || null;
  }

  /**
   * Initialize LLM classifier (Gemma 4B or similar)
   */
  async initialize(): Promise<void> {
    if (this.useLLM && !this.classifier) {
      try {
        // Try to load local LLM for intent classification
        // @ts-ignore
        const { pipeline } = await import('@xenova/transformers').catch(() => null) || {};
        if (pipeline) {
          const classifier = await pipeline('zero-shot-classification', 'Xenova/mobilebert-uncased-mnli');
          this.classifier = {
            classify: async (userQuery: string) => {
              const result = await classifier(userQuery, [
                'summarize document',
                'analyze data',
                'generate content',
                'search information',
                'modify files',
                'delete data',
                'send data externally',
                'access credentials',
              ]);
              const r = result as any;
              return {
                intent: r.labels[0],
                confidence: r.scores[0],
              };
            },
          };
          this.emit('initialized', { type: 'llm', model: 'mobilebert-uncased-mnli' });
        }
      } catch (err) {
        this.emit('initialized', { type: 'rule-based', error: err });
      }
    } else {
      this.emit('initialized', { type: 'rule-based' });
    }
  }

  /**
   * Analyze user intent vs agent action using LLM or heuristics
   */
  async analyze(userQuery: string, plannedActions: string[], sessionId?: string): Promise<IntentAnalysis> {
    const session = this.getOrCreateSession(sessionId);
    
    // Extract user goal
    let userGoal: string;
    let confidence: number;
    
    if (this.classifier) {
      const classification = await this.classifier.classify(userQuery);
      userGoal = classification.intent;
      confidence = classification.confidence;
    } else {
      const heuristic = this.extractGoalHeuristic(userQuery);
      userGoal = heuristic.goal;
      confidence = heuristic.confidence;
    }

    // Analyze agent action
    const agentAction = plannedActions[plannedActions.length - 1] || 'unknown';
    
    // Detect gaps between intent and action
    const gaps = this.detectGaps(userGoal, agentAction, plannedActions, userQuery);
    
    // Calculate risk
    const riskLevel = this.calculateRisk(userGoal, agentAction, gaps, confidence);
    
    // Generate explanation
    const explanation = this.generateExplanation(userGoal, agentAction, gaps, riskLevel);

    // Log session activity
    session.intents.push(userGoal);
    session.actions.push(agentAction);

    const analysis: IntentAnalysis = {
      userGoal,
      agentAction,
      confidence,
      gaps,
      riskLevel,
      explanation,
    };

    this.emit('analyzed', { sessionId: session.id, analysis });
    return analysis;
  }

  /**
   * Validate and potentially block action
   */
  async validate(
    userIntent: string,
    action: string,
    context?: { data?: string; destination?: string }
  ): Promise<{ allowed: boolean; reason?: string; severity?: SIFAlert['severity'] }> {
    const actionLower = action.toLowerCase();
    const intentLower = userIntent.toLowerCase();
    
    // Check 1: Exfiltration prevention
    const isExfilAttempt = this.exfilPatterns.some(p => actionLower.includes(p));
    const hasSendIntent = this.exfilPatterns.some(p => intentLower.includes(p)) ||
                         intentLower.includes('send') ||
                         intentLower.includes('share');
    
    if (isExfilAttempt && !hasSendIntent) {
      const reason = `Autonomous exfiltration blocked: action "${action}" not authorized by user intent`;
      this.logAlert(userIntent, action, reason, 'critical');
      return { allowed: false, reason, severity: 'critical' };
    }

    // Check 2: Destructive actions without authorization
    const isDestructive = this.destructivePatterns.some(p => actionLower.includes(p));
    const hasDeleteIntent = intentLower.includes('delete') ||
                           intentLower.includes('remove') ||
                           intentLower.includes('clear');
    
    if (isDestructive && !hasDeleteIntent) {
      const reason = `Destructive action blocked: "${action}" not authorized by user intent`;
      this.logAlert(userIntent, action, reason, 'high');
      return { allowed: false, reason, severity: 'high' };
    }

    // Check 3: Custom blocked patterns
    for (const pattern of this.blockedPatterns) {
      if (actionLower.includes(pattern)) {
        const reason = `Action matches blocked pattern: ${pattern}`;
        this.logAlert(userIntent, action, reason, 'high');
        return { allowed: false, reason, severity: 'high' };
      }
    }

    // Check 4: Sensitive data access
    const accessesSensitive = this.sensitivePatterns.some(p => actionLower.includes(p));
    if (accessesSensitive && !intentLower.includes('password') && !intentLower.includes('credential')) {
      // Allow but warn
      this.emit('warning', { type: 'sensitive_access', action, intent: userIntent });
    }

    // Log allowed action
    this.log.push({ ts: Date.now(), intent: userIntent, action, blocked: false, sessionId: 'default' });
    
    return { allowed: true };
  }

  /**
   * Extract goal using heuristics (fallback when no LLM)
   */
  private extractGoalHeuristic(query: string): { goal: string; confidence: number } {
    const lower = query.toLowerCase();
    
    const patterns: Array<{ pattern: RegExp; goal: string; weight: number }> = [
      { pattern: /summarize|summarize|tldr|brief/, goal: 'summarize_content', weight: 0.9 },
      { pattern: /analyze|analysis|examine|evaluate/, goal: 'analyze_data', weight: 0.85 },
      { pattern: /generate|create|write|compose/, goal: 'gen_content', weight: 0.85 },
      { pattern: /search|find|lookup|query/, goal: 'search_info', weight: 0.9 },
      { pattern: /delete|remove|erase|clear/, goal: 'delete_data', weight: 0.95 },
      { pattern: /send|email|share|transfer|upload/, goal: 'send_data', weight: 0.9 },
      { pattern: /modify|edit|update|change|patch/, goal: 'modify_data', weight: 0.85 },
      { pattern: /read|open|view|display/, goal: 'read_data', weight: 0.9 },
      { pattern: /compare|contrast|diff/, goal: 'compare_items', weight: 0.8 },
      { pattern: /debug|fix|repair|solve/, goal: 'debug_issue', weight: 0.85 },
    ];

    for (const { pattern, goal, weight } of patterns) {
      if (pattern.test(lower)) {
        return { goal, confidence: weight };
      }
    }

    return { goal: 'unknown', confidence: 0.5 };
  }

  /**
   * Detect gaps between intent and action
   */
  private detectGaps(goal: string, action: string, plan: string[], query: string): string[] {
    const gaps: string[] = [];
    const actionLower = action.toLowerCase();
    const queryLower = query.toLowerCase();
    
    // Gap 1: Action not mentioned in query
    const actionWords = actionLower.split(/[_\s]+/);
    const hasRelatedWord = actionWords.some(w => 
      w.length > 3 && queryLower.includes(w)
    );
    if (!hasRelatedWord && !queryLower.includes(actionLower)) {
      gaps.push('action_not_in_intent');
    }

    // Gap 2: Destructive without explicit permission
    if (this.destructivePatterns.some(p => actionLower.includes(p))) {
      const hasDeletePerm = queryLower.includes('delete') ||
                           queryLower.includes('remove') ||
                           queryLower.includes('clean up');
      if (!hasDeletePerm) {
        gaps.push('destructive_without_permission');
      }
    }

    // Gap 3: Data exfiltration
    if (this.exfilPatterns.some(p => actionLower.includes(p))) {
      const hasSendPerm = this.exfilPatterns.some(p => queryLower.includes(p));
      if (!hasSendPerm) {
        gaps.push('unauthorized_exfiltration');
      }
    }

    // Gap 4: Scope expansion
    if (plan.length > 3 && !queryLower.includes('and then') && !queryLower.includes('step by step')) {
      gaps.push('complex_plan_may_expand_scope');
    }

    return gaps;
  }

  /**
   * Calculate risk level
   */
  private calculateRisk(
    goal: string,
    action: string,
    gaps: string[],
    confidence: number
  ): IntentAnalysis['riskLevel'] {
    // Critical: Exfiltration
    if (gaps.some(g => g.includes('exfiltration'))) {
      return 'critical';
    }

    // High: Destructive or many gaps
    if (gaps.some(g => g.includes('destructive')) || gaps.length > 2) {
      return 'high';
    }

    // High: Mismatch with high confidence
    if (gaps.length > 0 && confidence > 0.8) {
      return 'high';
    }

    // Medium: Some gaps or low confidence
    if (gaps.length > 0 || confidence < 0.6) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Generate human-readable explanation
   */
  private generateExplanation(
    goal: string,
    action: string,
    gaps: string[],
    risk: IntentAnalysis['riskLevel']
  ): string {
    if (gaps.length === 0) {
      return `Action "${action}" aligns with goal "${goal}". Low risk.`;
    }

    const gapDescriptions: Record<string, string> = {
      'action_not_in_intent': 'Action was not explicitly mentioned in user request',
      'destructive_without_permission': 'Destructive action without explicit user authorization',
      'unauthorized_exfiltration': 'Data transfer attempt without user authorization',
      'complex_plan_may_expand_scope': 'Multi-step plan may exceed user intent scope',
    };

    const gapList = gaps.map(g => gapDescriptions[g] || g).join('; ');
    return `Risk ${risk}: ${gapList}`;
  }

  /**
   * Log security alert
   */
  private logAlert(
    intent: string,
    action: string,
    reason: string,
    severity: SIFAlert['severity']
  ): void {
    const alert: SIFAlert = {
      id: randomUUID(),
      timestamp: Date.now(),
      userIntent: intent,
      blockedAction: action,
      reason,
      severity,
      action: 'blocked',
      sessionId: 'default',
    };
    
    this.alerts.push(alert);
    this.emit('alert', alert);
    this.log.push({ ts: Date.now(), intent, action, blocked: true, sessionId: 'default' });
  }

  /**
   * Get or create session
   */
  private getOrCreateSession(id?: string): { id: string; intents: string[]; actions: string[]; createdAt: number } {
    const sessionId = id || `session-${Date.now()}`;
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, { id: sessionId, intents: [], actions: [], createdAt: Date.now() });
    }
    return this.sessions.get(sessionId)!;
  }

  /**
   * Add custom blocked pattern
   */
  addPattern(pattern: string): void {
    this.blockedPatterns.add(pattern.toLowerCase());
    this.emit('pattern:added', { pattern });
  }

  /**
   * Remove blocked pattern
   */
  removePattern(pattern: string): void {
    this.blockedPatterns.delete(pattern.toLowerCase());
  }

  /**
   * Get security alerts
   */
  getAlerts(severity?: SIFAlert['severity']): SIFAlert[] {
    let alerts = this.alerts;
    if (severity) {
      alerts = alerts.filter(a => a.severity === severity);
    }
    return alerts.slice(-100);
  }

  /**
   * Get session activity log
   */
  getSession(sessionId?: string): Array<{ ts: number; intent: string; action: string; blocked: boolean }> {
    if (sessionId) {
      return this.log.filter(l => l.sessionId === sessionId);
    }
    return [...this.log];
  }

  /**
   * Get real-time dashboard data
   */
  getDashboard(): SIFDashboard {
    const now = Date.now();
    const dayAgo = now - 86400000;
    
    const bySeverity: Record<string, number> = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };

    for (const alert of this.alerts) {
      bySeverity[alert.severity] = (bySeverity[alert.severity] ?? 0) + 1;
    }

    const last24h = this.alerts.filter(a => a.timestamp > dayAgo).length;
    const blockedActions = this.log.filter(l => l.blocked).length;
    const totalActions = this.log.length;
    const blockedRate = totalActions > 0 ? (blockedActions / totalActions) * 100 : 0;

    // Clean old sessions
    for (const [id, session] of this.sessions) {
      if (session.createdAt < dayAgo) {
        this.sessions.delete(id);
      }
    }

    return {
      total: this.alerts.length,
      bySeverity,
      last24h,
      blockedRate,
      activeSessions: this.sessions.size,
    };
  }

  /**
   * Stream dashboard updates
   */
  startDashboardStream(intervalMs: number = 5000): () => void {
    const interval = setInterval(() => {
      this.emit('dashboard:update', this.getDashboard());
    }, intervalMs);

    return () => clearInterval(interval);
  }

  /**
   * Get current status
   */
  getStatus(): {
    initialized: boolean;
    useLLM: boolean;
    totalAlerts: number;
    blockedPatterns: number;
    sessions: number;
  } {
    return {
      initialized: true,
      useLLM: this.useLLM && this.classifier !== null,
      totalAlerts: this.alerts.length,
      blockedPatterns: this.blockedPatterns.size,
      sessions: this.sessions.size,
    };
  }

  /**
   * Clear all data
   */
  clear(): void {
    this.alerts = [];
    this.log = [];
    this.sessions.clear();
    this.emit('cleared');
  }
}

export default SemanticIntentFirewall;
