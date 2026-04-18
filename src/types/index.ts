/**
 * Project Arniko — Core Types
 * AI Security Platform type definitions
 */

// ─── Scan Types ───────────────────────────────────────────────────────────────

export type ScanTool =
  | 'garak'           // LLM vulnerability scanner
  | 'semgrep'         // Static analysis
  | 'trufflehog'      // Secret scanning
  | 'trivy'           // Container security
  | 'bandit'          // Python security
  | 'eslint-security' // JS security rules
  | 'custom';         // User-defined

export type ScanSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface ScanTarget {
  type: 'llm_endpoint' | 'codebase' | 'container' | 'config';
  identifier: string;      // URL, path, image name, etc.
  metadata?: Record<string, unknown>;
}

export interface ScanFinding {
  id: string;
  tool: ScanTool;
  severity: ScanSeverity;
  title: string;
  description: string;
  remediation?: string;
  evidence?: string | Record<string, unknown>;  // Snippet or log excerpt
  location?: {
    file?: string;
    line?: number;
    column?: number;
    endpoint?: string;
  };
  cwe?: string;            // CWE-ID (e.g., "CWE-89")
  owasp?: string;          // OWASP category
  category?: string;       // Tool-specific category label
  timestamp?: Date;        // When finding was produced
  metadata?: Record<string, unknown>;
}

export interface ScanResult {
  scanId: string;
  status: ScanStatus;
  tool: ScanTool;
  target: ScanTarget;
  findings: ScanFinding[];
  startedAt: Date;
  completedAt?: Date;
  durationMs?: number;
  error?: string;
  metadata?: Record<string, unknown>;
}

// Benchmark Types for PurpleLlama
export interface BenchmarkResult {
  benchmark: string;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  averageSafetyScore: number;
  findings: SecurityFinding[];
  duration: number;
  timestamp: string;
  error?: string;
}

export interface SecurityFinding {
  testId: string;
  benchmark: string;
  category: string;
  severity: string;
  prompt: string;
  response: string;
  safetyScore: number;
  passed: boolean;
  timestamp: string;
  error?: string;
  metadata?: Record<string, unknown>;
}

// ─── Garak Types ──────────────────────────────────────────────────────────────

export interface GarakConfig {
  endpoint: string;         // LLM API endpoint to probe
  apiKey?: string;          // API key for the endpoint
  probes: GarakProbe[];     // Which probes to run
  maxRetries?: number;
  timeoutMs?: number;
}

export type GarakProbe =
  | 'jailbreak'
  | 'prompt_injection'
  | 'data_exfiltration'
  | 'encoding_attacks'
  | 'roleplay_attacks'
  | 'dan_variants'
  | 'system_prompt_leak'
  | 'all';

export interface GarakFinding extends ScanFinding {
  probe: GarakProbe;
  successRate: number;      // 0-1, how often the attack succeeded
  sampleAttacks: string[];  // Example attack strings that worked
}

// ─── Semgrep Types ────────────────────────────────────────────────────────────

export interface SemgrepConfig {
  path: string;             // Directory to scan
  rules: string[];          // Rule sets to apply
  excludePatterns?: string[];
  maxFileSize?: number;     // Skip files larger than this (bytes)
}

export interface SemgrepFinding extends ScanFinding {
  ruleId: string;
  ruleMessage: string;
  fix?: string;             // Suggested code fix
}

// ─── TruffleHog Types ─────────────────────────────────────────────────────────

export interface TruffleHogConfig {
  path?: string;            // Directory to scan
  gitRepo?: string;         // Git repo URL to scan
  onlyVerified?: boolean;   // Only report verified secrets
  since?: string;           // Git commit hash to scan from
  excludePaths?: string[];  // Paths to exclude
  includePaths?: string[];  // Paths to include
  simulation?: boolean;
  [key: string]: unknown;
}

export interface TruffleHogFinding extends ScanFinding {
  secretType: string;       // e.g., "AWS Access Key", "GitHub Token"
  detector: string;         // Detector that found the secret
  verified: boolean;        // Whether the secret is confirmed live
  redactedSecret: string;   // First 4 + last 4 chars only
  sourceMetadata?: {
    file?: string;
    line?: number;
    commit?: string;
    branch?: string;
  };
}

// ─── Trivy Types ──────────────────────────────────────────────────────────────

export interface TrivyConfig {
  target?: string;          // Container image or directory path
  scanners?: TrivyScanner[] | string[];
  severity?: ScanSeverity[] | string[];
  format?: 'json' | 'sarif' | 'table';
  skipUpdate?: boolean;
  ignoreUnfixed?: boolean;
  [key: string]: unknown;
}

export type TrivyScanner = 'vuln' | 'secret' | 'config' | 'license';

export interface TrivyFinding extends ScanFinding {
  pkgName?: string;         // Vulnerable package name
  pkgVersion?: string;      // Vulnerable package version
  fixedVersion?: string;    // Version with the fix
  cvss?: {
    v3Score?: number;
    v3Vector?: string;
  };
  publishedDate?: Date;
  lastModifiedDate?: Date;
}

// ─── Shield Integration Types ─────────────────────────────────────────────────

export interface ShieldEvent {
  id: string;
  userId: string;
  type: 'blocked_request' | 'pii_redacted' | 'budget_exceeded' | 'anomaly_detected';
  severity: ScanSeverity;
  inputHash: string;        // Hash of input (never store raw)
  reason: string;
  metadata?: Record<string, unknown>;
  timestamp: Date;
}

export interface ShieldMetrics {
  totalRequests: number;
  blockedRequests: number;
  redactedOutputs: number;
  budgetStops: number;
  blockRate: number;        // blockedRequests / totalRequests
  topBlockReasons: Array<{ reason: string; count: number }>;
  period: {
    start: Date;
    end: Date;
  };
}

// ─── Dashboard Types ──────────────────────────────────────────────────────────

export interface RiskScore {
  userId?: string;
  appId?: string;
  overall: number;          // 0-100
  components: {
    injectionRisk: number;
    piiRisk: number;
    costRisk: number;
    secretRisk: number;
  };
  trend: 'improving' | 'stable' | 'worsening';
  lastUpdated: Date;
}

export interface ScanSummary {
  totalScans: number;
  openFindings: number;
  criticalFindings: number;
  highFindings: number;
  resolvedThisWeek: number;
  topVulnerableTools: ScanTool[];
}

// ─── API Types ────────────────────────────────────────────────────────────────

export interface ScanRequest {
  tools: ScanTool[];
  target: ScanTarget;
  options?: {
    simulation?: boolean;
    garak?: Record<string, unknown>;
    llmGuard?: Record<string, unknown>;
    rebuff?: Record<string, unknown>;
    nemoGuardrails?: Record<string, unknown>;
    purpleLlama?: Record<string, unknown>;
    promptfoo?: Record<string, unknown>;
    vigil?: Record<string, unknown>;
    semgrep?: Record<string, unknown>;
    codeql?: Record<string, unknown>;
    bandit?: Record<string, unknown>;
    trufflehog?: Record<string, unknown>;
    gitleaks?: Record<string, unknown>;
    trivy?: Record<string, unknown>;
    grype?: Record<string, unknown>;
    checkov?: Record<string, unknown>;
    falco?: Record<string, unknown>;
    socket?: Record<string, unknown>;
    snyk?: Record<string, unknown>;
    owaspDependencyCheck?: Record<string, unknown>;
  };
}

export interface ScanResponse {
  scanId: string;
  status: ScanStatus;
  message: string;
  estimatedDurationMs?: number;
}

export interface FindingsResponse {
  scanId: string;
  results: ScanResult[];
  summary: {
    total: number;
    bySeverity: Record<ScanSeverity, number>;
    byTool: Record<ScanTool, number>;
  };
}

// ─── Config ───────────────────────────────────────────────────────────────────

export interface ArnikoConfig {
  shield: {
    enabled: boolean;
    dailyBudgetUSD: number;
    enableMLDetection: boolean;
  };
  scanners: {
    garak: boolean;
    semgrep: boolean;
    trufflehog: boolean;
    trivy: boolean;
  };
  alerts: {
    slack?: { webhookUrl: string };
    pagerduty?: { integrationKey: string };
    email?: { to: string[] };
  };
  database: {
    neonUrl: string;
  };
}
