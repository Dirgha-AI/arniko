/**
 * Types for Arniko Security Platform Risk Calculator
 */

interface Finding {
  tool: string;
  severity: string;
}

interface ShieldEvent {
  event_type: string;
  severity: string;
}

interface RiskScoreResult {
  overall: number;
  injectionRisk: number;
  piiRisk: number;
  costRisk: number;
  secretRisk: number;
  trend: 'improving' | 'stable' | 'worsening';
}

/**
 * RiskCalculator class for Arniko security platform.
 * Calculates risk scores based on security findings and shield events.
 * Maintains internal state to track trend across multiple calculations.
 */
export class RiskCalculator {
  private previousOverallScore: number | null = null;

  private readonly severityWeights: Record<string, number> = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3,
  };

  private getSeverityScore(severity: string): number {
    return this.severityWeights[severity.toLowerCase()] || 0;
  }

  private capAt100(score: number): number {
    return Math.min(Math.round(score), 100);
  }

  /**
   * Calculate risk scores based on findings and shield events.
   * @param findings Array of security findings from various tools
   * @param shieldEvents Array of shield security events
   * @returns RiskScoreResult containing individual risk categories, overall score, and trend
   */
  calculateRisk(
    findings: Finding[] = [],
    shieldEvents: ShieldEvent[] = []
  ): RiskScoreResult {
    // Calculate Injection Risk (Garak + Shield blocked requests)
    const garakScore = findings
      .filter((f) => f.tool.toLowerCase() === 'garak')
      .reduce((sum, f) => sum + this.getSeverityScore(f.severity), 0);

    const blockedRequestScore = shieldEvents
      .filter((e) => e.event_type.toLowerCase() === 'blocked_request')
      .reduce((sum, e) => sum + this.getSeverityScore(e.severity), 0);

    const injectionRisk = this.capAt100(garakScore + blockedRequestScore);

    // Calculate PII Risk (Shield PII redacted + Semgrep findings)
    const piiRedactedScore = shieldEvents
      .filter((e) => e.event_type.toLowerCase() === 'pii_redacted')
      .reduce((sum, e) => sum + this.getSeverityScore(e.severity), 0);

    const semgrepScore = findings
      .filter((f) => f.tool.toLowerCase() === 'semgrep')
      .reduce((sum, f) => sum + this.getSeverityScore(f.severity), 0);

    const piiRisk = this.capAt100(piiRedactedScore + semgrepScore);

    // Calculate Cost Risk (Shield budget exceeded)
    const costRisk = this.capAt100(
      shieldEvents
        .filter((e) => e.event_type.toLowerCase() === 'budget_exceeded')
        .reduce((sum, e) => sum + this.getSeverityScore(e.severity), 0)
    );

    // Calculate Secret Risk (TruffleHog + Trivy)
    const trufflehogScore = findings
      .filter((f) => f.tool.toLowerCase() === 'trufflehog')
      .reduce((sum, f) => sum + this.getSeverityScore(f.severity), 0);

    const trivyScore = findings
      .filter((f) => f.tool.toLowerCase() === 'trivy')
      .reduce((sum, f) => sum + this.getSeverityScore(f.severity), 0);

    const secretRisk = this.capAt100(trufflehogScore + trivyScore);

    // Calculate weighted overall score
    const overall = this.capAt100(
      injectionRisk * 0.30 +
      piiRisk * 0.25 +
      costRisk * 0.20 +
      secretRisk * 0.25
    );

    // Determine trend
    let trend: 'improving' | 'stable' | 'worsening' = 'stable';
    
    if (this.previousOverallScore !== null) {
      const difference = overall - this.previousOverallScore;
      if (difference < -5) {
        trend = 'improving';
      } else if (difference > 5) {
        trend = 'worsening';
      }
    }

    // Store current score for next comparison
    this.previousOverallScore = overall;

    return {
      overall,
      injectionRisk,
      piiRisk,
      costRisk,
      secretRisk,
      trend,
    };
  }

  /**
   * Reset the trend tracking by clearing the previous score history.
   * Next calculation will have 'stable' trend.
   */
  resetTrendHistory(): void {
    this.previousOverallScore = null;
  }

  /**
   * Manually set the previous score for trend calculation.
   * Useful for initializing the calculator with historical data.
   */
  setPreviousScore(score: number): void {
    this.previousOverallScore = score;
  }
}

/**
 * Standalone function to calculate risk score.
 * Note: This creates a new calculator instance each time, so trend will always be 'stable'.
 * For trend tracking across multiple calculations, use the RiskCalculator class directly.
 * 
 * @param findings Array of security findings from various tools
 * @param shieldEvents Array of shield security events
 * @returns RiskScoreResult containing individual risk categories and overall score
 */
export function calculateRiskScore(
  findings: Finding[] = [],
  shieldEvents: ShieldEvent[] = []
): RiskScoreResult {
  const calculator = new RiskCalculator();
  return calculator.calculateRisk(findings, shieldEvents);
}