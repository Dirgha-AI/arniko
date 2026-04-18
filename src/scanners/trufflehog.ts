/**
 * TruffleHog Scanner Adapter
 *
 * Scans for secrets and credentials in codebases.
 * Uses TruffleHog v3 (Go binary) with JSON output format.
 *
 * Requires: trufflehog (brew install trufflesecurity/trufflehog/trufflehog)
 * Or download from: https://github.com/trufflesecurity/trufflehog/releases
 * 
 * Production-ready implementation with:
 * - Support for filesystem, git repository, and docker scanning
 * - Verified vs unverified secret detection
 * - Proper severity mapping based on verification status
 * - Robust error handling and timeout management
 */

import { spawn } from 'child_process';
import { randomUUID } from 'crypto';
import type { ScanResult, ScanFinding, ScanSeverity, ScanTarget, TruffleHogConfig } from '../types/index.js';

/**
 * Internal type representing a TruffleHog raw JSON finding.
 */
interface TruffleHogRawFinding {
  SourceMetadata?: {
    Data?: {
      Git?: {
        commit?: string;
        file?: string;
        line?: number;
        branch?: string;
        email?: string;
        timestamp?: string;
        repository?: string;
        link?: string;
      };
      Filesystem?: {
        file?: string;
        line?: number;
      };
      Docker?: {
        file?: string;
        layer?: string;
      };
    };
  };
  DetectorName?: string;
  DecoderName?: string;
  Verified?: boolean;
  Raw?: string;
  RawV2?: string;
  Redacted?: string;
  ExtraData?: Record<string, unknown>;
  StructuredData?: Record<string, unknown>;
}

export class TruffleHogScanner {
  private config: TruffleHogConfig;
  private readonly DEFAULT_TIMEOUT = 300000; // 5 minutes

  constructor(config: TruffleHogConfig = {}) {
    this.config = {
      onlyVerified: false,
      ...config
    };
  }

  /**
   * Executes a secret detection scan against the provided target.
   * 
   * @param {ScanTarget} target - The target to scan
   * @returns {Promise<ScanResult>} Promise resolving to standardized scan results
   */
  async run(target: ScanTarget): Promise<ScanResult> {
    const scanId = randomUUID();
    const startedAt = new Date();

    try {
      const isInstalled = await this.checkInstalled();
      
      if (!isInstalled) {
        return this.createErrorResult(
          scanId,
          target,
          startedAt,
          'TruffleHog is not installed. Install from https://github.com/trufflesecurity/trufflehog'
        );
      }

      // Determine target path/URL from the scan target
      const scanTarget = this.determineScanTarget(target);
      
      if (!scanTarget) {
        return this.createErrorResult(
          scanId,
          target,
          startedAt,
          'Unable to determine scan target from provided ScanTarget'
        );
      }

      const rawFindings = await this.runCLI(scanTarget);
      const standardizedFindings = this.standardizeFindings(rawFindings, target);
      
      const completedAt = new Date();

      return {
        scanId,
        status: 'completed',
        tool: 'trufflehog',
        target,
        findings: standardizedFindings,
        startedAt,
        completedAt,
        durationMs: completedAt.getTime() - startedAt.getTime(),
        metadata: {
          totalDetections: rawFindings.length,
          verifiedCount: rawFindings.filter(f => f.Verified).length,
          unverifiedCount: rawFindings.filter(f => !f.Verified).length,
          onlyVerified: this.config.onlyVerified,
        }
      };
    } catch (error) {
      const completedAt = new Date();
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      return {
        scanId,
        status: 'failed',
        tool: 'trufflehog',
        target,
        findings: [],
        startedAt,
        completedAt,
        durationMs: completedAt.getTime() - startedAt.getTime(),
        error: errorMessage,
      };
    }
  }

  /**
   * Determines the appropriate scan target string based on ScanTarget.
   */
  private determineScanTarget(target: ScanTarget): string | null {
    // If gitRepo is configured in the config, use that
    if (this.config.gitRepo) {
      return this.config.gitRepo;
    }

    // If path is configured in the config, use that
    if (this.config.path) {
      return this.config.path;
    }

    // Otherwise use the target identifier
    if (target.identifier) {
      return target.identifier;
    }

    // Check metadata for additional paths
    if (target.metadata?.['path']) {
      return String(target.metadata['path']);
    }

    return null;
  }

  /**
   * Verifies that the TruffleHog CLI is installed and accessible.
   * 
   * @returns {Promise<boolean>} True if TruffleHog is installed
   */
  async checkInstalled(): Promise<boolean> {
    return new Promise((resolve) => {
      const proc = spawn('trufflehog', ['--version'], { 
        stdio: 'pipe',
        timeout: 10000 
      });
      
      let timedOut = false;
      const timeout = setTimeout(() => {
        timedOut = true;
        proc.kill();
        resolve(false);
      }, 10000);

      proc.on('error', () => {
        clearTimeout(timeout);
        resolve(false);
      });

      proc.on('close', (code) => {
        clearTimeout(timeout);
        if (timedOut) return;
        resolve(code === 0);
      });
    });
  }

  /**
   * Executes the TruffleHog CLI command with appropriate arguments.
   * 
   * @param {string} target - The target to scan
   * @returns {Promise<TruffleHogRawFinding[]>} Raw findings from TruffleHog
   */
  private runCLI(target: string): Promise<TruffleHogRawFinding[]> {
    return new Promise((resolve, reject) => {
      const args: string[] = ['--json'];

      // Add filtering options
      if (this.config.onlyVerified) {
        args.push('--only-verified');
      }

      if (this.config.since) {
        args.push('--since-commit', this.config.since);
      }

      // Add verbosity for more context
      args.push('--verifiers=all');

      // Determine the scan type based on target format
      let command: string;
      let targetArg: string;

      if (target.startsWith('http://') || target.startsWith('https://') || target.startsWith('git@')) {
        // Remote git repository
        command = 'git';
        targetArg = target;
      } else if (target.includes('.git')) {
        // Local git repository
        command = 'git';
        targetArg = `file://${target}`;
      } else if (target.startsWith('docker://') || target.includes('docker')) {
        // Docker image
        command = 'docker';
        targetArg = target.replace('docker://', '');
      } else {
        // Filesystem (default)
        command = 'filesystem';
        targetArg = target;
      }

      args.unshift(command, targetArg);

      // Add exclude patterns if configured
      if (this.config.excludePaths && this.config.excludePaths.length > 0) {
        for (const pattern of this.config.excludePaths) {
          args.push('--exclude-paths', pattern);
        }
      }

      // Add include paths if configured
      if (this.config.includePaths && this.config.includePaths.length > 0) {
        for (const pattern of this.config.includePaths) {
          args.push('--include-paths', pattern);
        }
      }

      const proc = spawn('trufflehog', args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: this.DEFAULT_TIMEOUT,
        killSignal: 'SIGTERM'
      });

      let stdout = '';
      let stderr = '';
      let timedOut = false;

      proc.stdout?.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      proc.stderr?.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      proc.on('error', (error) => {
        reject(new Error(`Failed to execute TruffleHog: ${error.message}`));
      });

      proc.on('close', (code, signal) => {
        if (timedOut) return;

        // Handle timeout
        if (signal === 'SIGTERM') {
          reject(new Error('TruffleHog scan timed out after 5 minutes'));
          return;
        }

        // TruffleHog exits with code 183 when secrets are found (not an error)
        // Exit code 0 means no secrets found
        // Other codes indicate errors
        if (code !== 0 && code !== 183 && code !== null) {
          reject(new Error(`TruffleHog exited with code ${code}: ${stderr || 'Unknown error'}`));
          return;
        }

        // Parse JSON lines (TruffleHog outputs one JSON object per line)
        const findings: TruffleHogRawFinding[] = [];
        const lines = stdout.split('\n').filter(line => line.trim());

        for (const line of lines) {
          try {
            const parsed = JSON.parse(line) as TruffleHogRawFinding;
            findings.push(parsed);
          } catch {
            // Skip lines that aren't valid JSON
            // These might be progress messages or errors
          }
        }

        resolve(findings);
      });
    });
  }

  /**
   * Converts raw TruffleHog findings to standardized ScanFinding format.
   */
  private standardizeFindings(rawFindings: TruffleHogRawFinding[], target: ScanTarget): ScanFinding[] {
    return rawFindings.map(raw => {
      const detectorName = raw.DetectorName || 'Unknown';
      const isVerified = raw.Verified === true;
      const severity = this.determineSeverity(isVerified, detectorName);
      
      const sourceMetadata = raw.SourceMetadata?.Data || {};
      const git = sourceMetadata.Git || {};
      const filesystem = sourceMetadata.Filesystem || {};
      const docker = sourceMetadata.Docker || {};

      // Determine location based on source type
      let file: string | undefined;
      let line: number | undefined;
      let commit: string | undefined;
      let branch: string | undefined;

      if (git.file) {
        file = git.file;
        line = git.line;
        commit = git.commit;
        branch = git.branch;
      } else if (filesystem.file) {
        file = filesystem.file;
        line = filesystem.line;
      } else if (docker.file) {
        file = docker.file;
      }

      // Create redacted version of the secret
      const rawSecret = raw.Raw || '';
      const redacted = rawSecret.length > 8
        ? `${rawSecret.slice(0, 4)}${'*'.repeat(rawSecret.length - 8)}${rawSecret.slice(-4)}`
        : '****';

      return {
        id: randomUUID(),
        tool: 'trufflehog',
        severity,
        title: `${isVerified ? 'VERIFIED' : 'POTENTIAL'} Secret: ${detectorName}`,
        description: this.createDescription(detectorName, isVerified, raw),
        remediation: this.createRemediation(detectorName, isVerified),
        evidence: redacted,
        location: {
          file,
          line,
        },
        metadata: {
          detectorName,
          decoderName: raw.DecoderName,
          verified: isVerified,
          redactedSecret: redacted,
          extraData: raw.ExtraData,
          structuredData: raw.StructuredData,
          commit,
          branch,
          repository: git.repository,
          dockerLayer: docker.layer,
          rawFinding: raw,
        }
      };
    });
  }

  /**
   * Determines severity based on verification status and detector type.
   */
  private determineSeverity(isVerified: boolean, detectorName: string): ScanSeverity {
    if (isVerified) {
      // Verified live secrets are always critical
      return 'critical';
    }

    // High-value targets get high severity even if unverified
    const highValueDetectors = [
      'AWS',
      'GitHub',
      'GitLab',
      'Slack',
      'Stripe',
      'PrivateKey',
      'OpenAI',
      'Azure',
      'GCP',
    ];

    if (highValueDetectors.some(d => detectorName.toLowerCase().includes(d.toLowerCase()))) {
      return 'high';
    }

    return 'medium';
  }

  /**
   * Creates a human-readable description for the finding.
   */
  private createDescription(detectorName: string, isVerified: boolean, raw: TruffleHogRawFinding): string {
    let description = `TruffleHog detected a potential ${detectorName} credential.`;
    
    if (isVerified) {
      description += ' This secret has been VERIFIED as live and active. Immediate action is required.';
    } else {
      description += ' This secret could not be verified and may be inactive or a false positive.';
    }

    if (raw.DecoderName && raw.DecoderName !== 'PLAIN') {
      description += ` The secret was decoded using ${raw.DecoderName}.`;
    }

    if (raw.ExtraData && Object.keys(raw.ExtraData).length > 0) {
      const extraInfo = Object.entries(raw.ExtraData)
        .map(([key, value]) => `${key}: ${value}`)
        .join(', ');
      description += ` Additional context: ${extraInfo}.`;
    }

    return description;
  }

  /**
   * Creates remediation guidance based on detector type.
   */
  private createRemediation(detectorName: string, isVerified: boolean): string {
    let remediation = isVerified 
      ? 'URGENT: This secret is verified as live. '
      : 'This secret should be treated as potentially active. ';

    remediation += `1. Immediately revoke the ${detectorName} credential from the provider dashboard. `;
    remediation += '2. Rotate all secrets in affected files and any systems that may have used this credential. ';
    remediation += '3. Review access logs for unauthorized usage. ';
    remediation += '4. Update your secret management practices to prevent future exposures. ';
    remediation += '5. Consider using secret scanning pre-commit hooks to prevent future commits.';

    return remediation;
  }

  /**
   * Creates a failed scan result with error information.
   */
  private createErrorResult(
    scanId: string,
    target: ScanTarget,
    startedAt: Date,
    errorMessage: string
  ): ScanResult {
    const completedAt = new Date();
    return {
      scanId,
      status: 'failed',
      tool: 'trufflehog',
      target,
      findings: [],
      startedAt,
      completedAt,
      durationMs: completedAt.getTime() - startedAt.getTime(),
      error: errorMessage,
    };
  }
}

/**
 * Factory function to create a TruffleHogScanner instance.
 * 
 * @param {TruffleHogConfig} config - Configuration for the TruffleHog scanner
 * @returns {TruffleHogScanner} Configured TruffleHogScanner instance
 */
export function createTruffleHogScanner(config: TruffleHogConfig = {}): TruffleHogScanner {
  return new TruffleHogScanner(config);
}
