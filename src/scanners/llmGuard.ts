import { randomUUID } from 'crypto';
import type { ScanResult, ScanTarget, ScanFinding, ScanStatus, ScanSeverity, ScanTool } from '../types/index.js';

/**
 * Configuration options for LLMGuardScanner
 * @interface LLMGuardConfig
 */
export interface LLMGuardConfig {
  /** 
   * LLM Guard API endpoint URL 
   * @default 'http://localhost:8000'
   */
  endpoint?: string;
  
  /** 
   * List of scanner names to use by default 
   * @example ['prompt_injection', 'pii', 'toxicity']
   */
  scanners: string[];
}

/**
 * Response structure from LLM Guard scan operations
 * @interface LLMGuardScanResponse
 */
export interface LLMGuardScanResponse {
  /** Whether the content passed all scanners */
  safe: boolean;
  /** Aggregate risk score (0.0 to 1.0, lower is safer) */
  score: number;
  /** Sanitized version of the input text */
  sanitized: string;
  /** Detailed results from each scanner */
  results: Array<{
    /** Name of the scanner */
    scanner: string;
    /** Whether this specific scan passed */
    valid: boolean;
    /** Score for this specific scanner */
    score: number;
  }>;
}

/**
 * Type guard to check if a scanner name is valid
 * @type {string}
 */
export type AvailableScanner = 
  | 'prompt_injection' 
  | 'ban_substrings' 
  | 'code' 
  | 'language' 
  | 'regex' 
  | 'secrets' 
  | 'sentiment' 
  | 'token_limit' 
  | 'toxicity' 
  | 'gibberish' 
  | 'invisible_text' 
  | 'pii';

/**
 * Adapter for LLM Guard (Laiyer AI) open-source LLM security toolkit.
 * Provides input/output sanitization via self-hosted API.
 * 
 * @class LLMGuardScanner
 * @example
 * const scanner = new LLMGuardScanner({
 *   endpoint: 'http://localhost:8000',
 *   scanners: ['prompt_injection', 'pii', 'toxicity']
 * });
 * 
 * const result = await scanner.scanInput("User prompt here");
 */
export class LLMGuardScanner {
  private readonly endpoint: string;
  private readonly defaultScanners: string[];
  
  /**
   * Available scanner types in LLM Guard
   * @static
   * @readonly
   */
  public static readonly AVAILABLE_SCANNERS: AvailableScanner[] = [
    'prompt_injection',
    'ban_substrings',
    'code',
    'language',
    'regex',
    'secrets',
    'sentiment',
    'token_limit',
    'toxicity',
    'gibberish',
    'invisible_text',
    'pii'
  ];

  /**
   * Creates an instance of LLMGuardScanner
   * @param {LLMGuardConfig} config - Configuration object
   * @throws {Error} If invalid scanner names are provided
   */
  constructor(config: LLMGuardConfig) {
    this.endpoint = config.endpoint?.replace(/\/$/, '') || 'http://localhost:8000';
    this.defaultScanners = config.scanners;

    // Validate scanner names
    const invalidScanners = this.defaultScanners.filter(
      scanner => !LLMGuardScanner.AVAILABLE_SCANNERS.includes(scanner as AvailableScanner)
    );
    
    if (invalidScanners.length > 0) {
      throw new Error(
        `Invalid scanner(s): ${invalidScanners.join(', ')}. ` +
        `Available scanners: ${LLMGuardScanner.AVAILABLE_SCANNERS.join(', ')}`
      );
    }
  }

  /**
   * Scans input prompt for security issues
   * 
   * @param {string} text - The prompt text to scan
   * @param {string[]} [scanners] - Override default scanners for this scan
   * @returns {Promise<LLMGuardScanResponse>} Scan results with safety status and sanitized text
   * @throws {Error} If the API request fails or network error occurs
   * 
   * @example
   * const result = await scanner.scanInput("Hello world");
   * if (!result.safe) {
   *   console.warn("Prompt rejected:", result.results);
   * }
   */
  async scanInput(text: string, scanners?: string[]): Promise<LLMGuardScanResponse> {
    const url = `${this.endpoint}/api/v1/scan/prompt`;
    const scannersToUse = scanners || this.defaultScanners;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          prompt: text,
          scanners: scannersToUse
        })
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => 'Unknown error');
        throw new Error(`LLM Guard API error (${response.status}): ${errorText}`);
      }

      const data = await response.json() as LLMGuardScanResponse;
      return data;
    } catch (error) {
      if (error instanceof Error && error.message.includes('fetch')) {
        throw new Error(`Network error connecting to LLM Guard at ${url}: ${error.message}`);
      }
      throw new Error(`Scan input failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Scans LLM output text for security issues
   * 
   * @param {string} text - The output text to scan
   * @param {string} prompt - The original prompt that generated this output (for context)
   * @param {string[]} [scanners] - Override default scanners for this scan
   * @returns {Promise<LLMGuardScanResponse>} Scan results with safety status
   * @throws {Error} If the API request fails
   * 
   * @example
   * const result = await scanner.scanOutput("Generated text", "Original prompt");
   * console.log("Output safe:", result.safe);
   */
  async scanOutput(text: string, prompt: string, scanners?: string[]): Promise<LLMGuardScanResponse> {
    const url = `${this.endpoint}/api/v1/scan/output`;
    const scannersToUse = scanners || this.defaultScanners;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          prompt: prompt,
          output: text,
          scanners: scannersToUse
        })
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => 'Unknown error');
        throw new Error(`LLM Guard API error (${response.status}): ${errorText}`);
      }

      const data = await response.json() as LLMGuardScanResponse;
      return data;
    } catch (error) {
      if (error instanceof Error && error.message.includes('fetch')) {
        throw new Error(`Network error connecting to LLM Guard at ${url}: ${error.message}`);
      }
      throw new Error(`Scan output failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Arniko orchestrator compatible scan method.
   * Wraps scanInput to conform to standard scanner interface.
   * 
   * @param {ScanTarget} target - The target content to scan (expects content/text property)
   * @returns {Promise<ScanResult>} Standardized scan result for orchestrator
   * @throws {Error} If scanning fails (returns error result rather than throwing in production)
   * 
   * @example
   * const target: ScanTarget = { content: "Hello world", metadata: {} };
   * const result = await scanner.run(target);
   */
  async run(target: ScanTarget): Promise<ScanResult> {
    const scanId = randomUUID();
    const startedAt = new Date();

    try {
      const text = (target.metadata?.text as string) || (target as any).content || (target as any).text || target.identifier || '';

      if (!text) {
        return { scanId, status: 'completed' as ScanStatus, tool: 'custom' as ScanTool, target, findings: [], startedAt, completedAt: new Date(), durationMs: 0, metadata: { note: 'No text provided' } };
      }

      const scanResult = await this.scanInput(text);
      const completedAt = new Date();

      const findings: ScanFinding[] = (scanResult.results || [])
        .filter((r: any) => !r.valid)
        .map((r: any) => ({
          id: randomUUID(),
          tool: 'custom' as ScanTool,
          severity: r.score > 0.8 ? 'high' : 'medium' as ScanSeverity,
          title: `LLM Guard: ${r.scanner} check failed`,
          description: `Scanner ${r.scanner} flagged input. Score: ${r.score?.toFixed(2) ?? 'N/A'}`,
          owasp: 'LLM01',
          metadata: { scanner: r.scanner, score: r.score, valid: r.valid },
        }));

      return { scanId, status: 'completed' as ScanStatus, tool: 'custom' as ScanTool, target, findings, startedAt, completedAt, durationMs: completedAt.getTime() - startedAt.getTime() };
    } catch (error) {
      return { scanId, status: 'failed' as ScanStatus, tool: 'custom' as ScanTool, target, findings: [], startedAt, completedAt: new Date(), durationMs: Date.now() - startedAt.getTime(), error: error instanceof Error ? error.message : String(error) };
    }
  }

  /**
   * Checks if LLM Guard API is available and healthy
   * 
   * @returns {Promise<boolean>} True if service is healthy, false otherwise
   * @example
   * if (await scanner.checkInstalled()) {
   *   console.log("LLM Guard is ready");
   * }
   */
  async checkInstalled(): Promise<boolean> {
    try {
      const response = await fetch(`${this.endpoint}/health`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json'
        }
      });
      return response.ok;
    } catch (error) {
      return false;
    }
  }

  /**
   * Simulates a scan without calling the API (mock fallback).
   * Useful for testing or when LLM Guard is unavailable.
   * 
   * @param {string} text - The text to "scan"
   * @returns {LLMGuardScanResponse} Mock scan result indicating safe/pass
   * @example
   * // Fallback when API is down
   * const result = scanner.simulateScan("Test prompt");
   */
  simulateScan(text: string): LLMGuardScanResponse {
    return {
      safe: true,
      score: 0.0,
      sanitized: text,
      results: this.defaultScanners.map(scanner => ({
        scanner,
        valid: true,
        score: 0.0
      }))
    };
  }

  /**
   * Get current configuration
   * @returns {Object} Current endpoint and scanners
   */
  getConfig(): { endpoint: string; scanners: string[] } {
    return {
      endpoint: this.endpoint,
      scanners: [...this.defaultScanners]
    };
  }
}

export default LLMGuardScanner;