import { spawn, ChildProcess } from 'child_process';
import { randomUUID } from 'crypto';
import type { ScanTarget, ScanResult, ScanStatus, ScanTool, ScanFinding } from '../types/index.js';

interface BaseScannerConfig {
  simulation?: boolean;
  [key: string]: unknown;
}

/**
 * Abstract base class for all Arniko security scanners.
 * Provides common functionality for tool installation checks, process spawning,
 * and result formatting. All concrete scanners must extend this class.
 */
export abstract class BaseScanner {
  protected tool: ScanTool;
  protected config: BaseScannerConfig;

  /**
   * Creates a new scanner instance.
   * @param tool - The scan tool configuration
   * @param config - Additional scanner-specific configuration
   */
  constructor(tool: ScanTool, config: BaseScannerConfig = {}) {
    this.tool = tool;
    this.config = config;
  }

  /**
   * Executes the scan workflow.
   * @param target - The target to scan
   * @returns Promise resolving to scan results
   */
  async run(target: ScanTarget): Promise<ScanResult> {
    const startTime = Date.now();
    const scanId = randomUUID();
    try {
      const isInstalled = await this.checkInstalled();
      if (!isInstalled || this.config.simulation) return this.simulateScan(scanId, target, startTime);
      return await this.executeScan(scanId, target, startTime);
    } catch (error) {
      return this.errorResult(scanId, target, startTime, error);
    }
  }

  /**
   * Binary name to execute (e.g., 'nmap', 'zap-cli').
   */
  protected abstract get binaryName(): string;

  /**
   * Flag to check version (e.g., '--version', '-v').
   */
  protected abstract get versionFlag(): string;

  /**
   * Execute the actual scan.
   * @param scanId - Unique scan identifier
   * @param target - Scan target
   * @param startTime - Scan start timestamp
   */
  protected abstract executeScan(scanId: string, target: ScanTarget, startTime: number): Promise<ScanResult>;

  /**
   * Simulate a scan for testing or when tool is unavailable.
   * @param scanId - Unique scan identifier
   * @param target - Scan target
   * @param startTime - Scan start timestamp
   */
  protected abstract simulateScan(scanId: string, target: ScanTarget, startTime: number): ScanResult;

  /**
   * Checks if the scanner binary is installed and accessible.
   * @returns Promise resolving to true if binary exists
   */
  protected async checkInstalled(): Promise<boolean> {
    try {
      const { exitCode } = await this.spawnProcess(this.binaryName, [this.versionFlag]);
      return exitCode === 0;
    } catch {
      return false;
    }
  }

  /**
   * Spawns a child process and captures output.
   * @param command - Command to execute
   * @param args - Command arguments
   * @returns Promise with stdout, stderr, and exit code
   */
  protected spawnProcess(command: string, args: string[]): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    return new Promise((resolve, reject) => {
      const child: ChildProcess = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';

      child.stdout?.on('data', (data: Buffer) => { stdout += data.toString(); });
      child.stderr?.on('data', (data: Buffer) => { stderr += data.toString(); });
      child.on('error', (err: Error) => reject(err));
      child.on('close', (code: number | null) => {
        resolve({ stdout, stderr, exitCode: code ?? 0 });
      });
    });
  }

  /**
   * Creates a failed scan result.
   * @param scanId - Unique scan identifier
   * @param target - Scan target
   * @param startTime - Scan start timestamp
   * @param error - Error that occurred
   */
  protected errorResult(scanId: string, target: ScanTarget, startTime: number, error: unknown): ScanResult {
    return {
      scanId,
      target,
      status: 'failed' as ScanStatus,
      findings: [],
      startedAt: new Date(startTime),
      completedAt: new Date(),
      durationMs: Date.now() - startTime,
      error: error instanceof Error ? error.message : String(error),
      tool: this.tool
    };
  }

  /**
   * Creates a successful scan result.
   * @param scanId - Unique scan identifier
   * @param target - Scan target
   * @param startTime - Scan start timestamp
   * @param findings - Discovered security findings
   */
  protected makeResult(scanId: string, target: ScanTarget, startTime: number, findings: ScanFinding[]): ScanResult {
    return {
      scanId,
      target,
      status: 'completed' as ScanStatus,
      findings,
      startedAt: new Date(startTime),
      completedAt: new Date(),
      durationMs: Date.now() - startTime,
      tool: this.tool
    };
  }
}
