import { spawn } from 'child_process';
import { randomUUID } from 'crypto';
import type {
  ScanResult,
  ScanFinding,
  ScanSeverity,
  ScanTarget,
  TrivyConfig,
  TrivyFinding
} from '../types/index.js';

/**
 * Trivy security scanner adapter for container images and filesystems.
 * Wraps the Aqua Security Trivy CLI to perform vulnerability scanning.
 * 
 * Production-ready implementation with:
 * - Robust error handling and timeout management
 * - Proper output parsing with validation
 * - Standardized severity mapping
 * - Support for filesystem, container images, and git repositories
 */
export class TrivyScanner {
  private config: TrivyConfig;
  private readonly DEFAULT_TIMEOUT = 300000; // 5 minutes
  private readonly DEFAULT_SCANNERS = ['vuln'];
  private readonly DEFAULT_SEVERITY = ['critical', 'high', 'medium'];

  constructor(config: TrivyConfig) {
    this.config = {
      scanners: this.DEFAULT_SCANNERS,
      severity: this.DEFAULT_SEVERITY,
      ...config
    };
  }

  /**
   * Executes a security scan against the provided target.
   * 
   * @param {ScanTarget} target - The target to scan (image, filesystem, or git repo)
   * @returns {Promise<ScanResult>} Promise resolving to standardized scan results
   */
  async run(target: ScanTarget): Promise<ScanResult> {
    const startedAt = new Date();
    const scanId = randomUUID();

    try {
      // Validate target type
      if (!['container', 'codebase', 'config'].includes(target.type)) {
        throw new Error(`Unsupported target type: ${target.type}. Trivy supports: container, codebase, config`);
      }

      const isInstalled = await this.checkInstalled();
      
      if (!isInstalled) {
        return this.createErrorResult(scanId, target, startedAt, 'Trivy CLI is not installed. Install from https://aquasecurity.github.io/trivy/');
      }

      const rawOutput = await this.runCLI(target);
      const trivyFindings = this.parseResult(rawOutput);
      const standardizedFindings = this.standardizeFindings(trivyFindings);
      
      const completedAt = new Date();

      return {
        scanId,
        status: 'completed',
        tool: 'trivy',
        target,
        findings: standardizedFindings,
        startedAt,
        completedAt,
        durationMs: completedAt.getTime() - startedAt.getTime(),
        metadata: {
          rawFindingCount: trivyFindings.length,
          scanners: this.config.scanners,
          severityFilter: this.config.severity,
        }
      };
    } catch (error) {
      const completedAt = new Date();
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      return {
        scanId,
        status: 'failed',
        tool: 'trivy',
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
   * Verifies that the Trivy CLI is installed and accessible.
   * 
   * @returns {Promise<boolean>} True if Trivy is installed
   */
  async checkInstalled(): Promise<boolean> {
    return new Promise((resolve) => {
      const proc = spawn('trivy', ['version'], { timeout: 10000 });
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

      proc.on('exit', (code) => {
        clearTimeout(timeout);
        if (timedOut) return;
        resolve(code === 0);
      });
    });
  }

  /**
   * Executes the Trivy CLI command with appropriate arguments.
   * 
   * @param {ScanTarget} target - The scan target
   * @returns {Promise<string>} Raw JSON output from Trivy
   */
  private runCLI(target: ScanTarget): Promise<string> {
    return new Promise((resolve, reject) => {
      const targetPath = target.identifier;
      
      // Determine command based on target type
      let command: string;
      if (target.type === 'container') {
        command = 'image';
      } else if (target.metadata?.['git']) {
        command = 'repo';
      } else {
        command = 'fs';
      }

      const args: string[] = [
        command,
        '--format', 'json',
        '--scanners', (this.config.scanners ?? []).join(','),
        '--severity', (this.config.severity ?? []).join(','),
      ];

      // Add skip-update for air-gapped environments if configured
      if (this.config.skipUpdate) {
        args.push('--skip-db-update');
      }

      // Add ignore unfixed vulnerabilities if configured
      if (this.config.ignoreUnfixed) {
        args.push('--ignore-unfixed');
      }

      args.push(targetPath);

      const proc = spawn('trivy', args, { 
        timeout: this.DEFAULT_TIMEOUT,
        killSignal: 'SIGTERM'
      });
      
      let stdout = '';
      let stderr = '';
      let timedOut = false;

      proc.stdout.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      proc.on('error', (error) => {
        reject(new Error(`Failed to execute Trivy: ${error.message}`));
      });

      proc.on('exit', (code, signal) => {
        if (timedOut) return;

        // Handle timeout
        if (signal === 'SIGTERM') {
          reject(new Error('Trivy scan timed out after 5 minutes'));
          return;
        }

        // Trivy exits with 0 even with vulnerabilities found
        // Exit code 1 indicates vulnerabilities were found (not an error)
        if (code !== 0 && code !== 1 && !stdout) {
          reject(new Error(`Trivy exited with code ${code}: ${stderr}`));
        } else {
          resolve(stdout);
        }
      });
    });
  }

  /**
   * Parses Trivy JSON output into TrivyFinding objects.
   * 
   * @param {string} rawOutput - Raw JSON string from Trivy CLI
   * @returns {TrivyFinding[]} Array of parsed findings
   */
  private parseResult(rawOutput: string): TrivyFinding[] {
    if (!rawOutput || rawOutput.trim() === '') {
      return [];
    }

    try {
      const parsed = JSON.parse(rawOutput);
      const findings: TrivyFinding[] = [];

      // Handle different Trivy output structures
      const results = parsed.Results || parsed.results || [];
      
      if (!Array.isArray(results)) {
        return findings;
      }

      for (const result of results) {
        // Process vulnerabilities
        const vulnerabilities = result.Vulnerabilities || result.vulnerabilities || [];
        
        if (Array.isArray(vulnerabilities)) {
          for (const vuln of vulnerabilities) {
            const finding = this.createFindingFromVulnerability(vuln, result);
            findings.push(finding);
          }
        }

        // Process secrets (misconfigurations/secrets scanner)
        const secrets = result.Secrets || result.secrets || [];
        
        if (Array.isArray(secrets)) {
          for (const secret of secrets) {
            const finding = this.createFindingFromSecret(secret, result);
            findings.push(finding);
          }
        }

        // Process misconfigurations
        const misconfigs = result.Misconfigurations || result.misconfigurations || [];
        
        if (Array.isArray(misconfigs)) {
          for (const misconfig of misconfigs) {
            const finding = this.createFindingFromMisconfiguration(misconfig, result);
            findings.push(finding);
          }
        }
      }

      return findings;
    } catch (error) {
      throw new Error(`Failed to parse Trivy JSON output: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Creates a TrivyFinding from a vulnerability entry.
   */
  private createFindingFromVulnerability(vuln: any, result: any): TrivyFinding {
    const cvss = this.extractCvssScore(vuln.CVSS || vuln.cvss);
    
    return {
      id: vuln.VulnerabilityID || vuln.vulnerabilityId || randomUUID(),
      tool: 'trivy',
      severity: this.mapSeverity(vuln.Severity || vuln.severity || 'UNKNOWN'),
      title: vuln.Title || vuln.title || vuln.VulnerabilityID || 'Unknown Vulnerability',
      description: vuln.Description || vuln.description || '',
      pkgName: vuln.PkgName || vuln.pkgName || vuln.PkgPath || 'unknown',
      pkgVersion: vuln.InstalledVersion || vuln.installedVersion || 'unknown',
      fixedVersion: vuln.FixedVersion || vuln.fixedVersion || 'not-fixed',
      cvss: cvss ? { v3Score: cvss } : undefined,
      location: {
        file: result.Target || result.target || vuln.PkgPath,
      },
      cwe: vuln.CweIDs?.[0] || vuln.cweId,
      metadata: {
        primaryUrl: vuln.PrimaryURL || vuln.primaryUrl,
        references: vuln.References || vuln.references,
        publishedDate: vuln.PublishedDate,
        lastModifiedDate: vuln.LastModifiedDate,
        scoreSource: vuln.ScoreSource,
        dataSource: vuln.DataSource,
      }
    };
  }

  /**
   * Creates a TrivyFinding from a secret entry.
   */
  private createFindingFromSecret(secret: any, result: any): TrivyFinding {
    return {
      id: randomUUID(),
      tool: 'trivy',
      severity: this.mapSeverity(secret.Severity || 'HIGH'),
      title: `Secret detected: ${secret.Title || secret.RuleID || 'Unknown'}`,
      description: secret.Match || secret.Description || 'Hardcoded secret detected',
      location: {
        file: result.Target || result.target || secret.Target,
        line: secret.StartLine || secret.startLine,
      },
      metadata: {
        ruleId: secret.RuleID || secret.ruleId,
        category: secret.Category || secret.category,
        match: secret.Match,
      }
    };
  }

  /**
   * Creates a TrivyFinding from a misconfiguration entry.
   */
  private createFindingFromMisconfiguration(misconfig: any, result: any): TrivyFinding {
    return {
      id: misconfig.ID || misconfig.id || randomUUID(),
      tool: 'trivy',
      severity: this.mapSeverity(misconfig.Severity || misconfig.severity || 'MEDIUM'),
      title: misconfig.Title || misconfig.title || 'Misconfiguration',
      description: misconfig.Description || misconfig.description || misconfig.Message || '',
      location: {
        file: result.Target || result.target,
        line: misconfig.CauseMetadata?.StartLine || misconfig.startLine,
      },
      metadata: {
        type: misconfig.Type,
        resolution: misconfig.Resolution,
        references: misconfig.References,
      }
    };
  }

  /**
   * Maps Trivy severity levels to standardized ScanSeverity.
   */
  private mapSeverity(severity: string): ScanSeverity {
    const normalized = severity.toUpperCase();
    switch (normalized) {
      case 'CRITICAL':
        return 'critical';
      case 'HIGH':
        return 'high';
      case 'MEDIUM':
        return 'medium';
      case 'LOW':
        return 'low';
      case 'UNKNOWN':
      default:
        return 'info';
    }
  }

  /**
   * Extracts the CVSS v3 score from Trivy CVSS data structure.
   */
  private extractCvssScore(cvss: any): number | undefined {
    if (!cvss || typeof cvss !== 'object') return undefined;

    // Try CVSS v3 scores from various sources (in order of preference)
    if (cvss.nvd?.V3Score !== undefined) return cvss.nvd.V3Score;
    if (cvss.redhat?.V3Score !== undefined) return cvss.redhat.V3Score;
    if (cvss.ghsa?.V3Score !== undefined) return cvss.ghsa.V3Score;
    if (cvss.glad?.V3Score !== undefined) return cvss.glad.V3Score;

    // Fallback to CVSS v2 if v3 not available
    if (cvss.nvd?.V2Score !== undefined) return cvss.nvd.V2Score;
    if (cvss.redhat?.V2Score !== undefined) return cvss.redhat.V2Score;

    // Direct v3Score/v2Score fields
    if (cvss.v3Score !== undefined) return cvss.v3Score;
    if (cvss.v2Score !== undefined) return cvss.v2Score;

    return undefined;
  }

  /**
   * Converts TrivyFinding objects to standardized ScanFinding format.
   */
  private standardizeFindings(findings: TrivyFinding[]): ScanFinding[] {
    return findings.map(finding => ({
      id: finding.id,
      tool: 'trivy',
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
      remediation: finding.fixedVersion && finding.fixedVersion !== 'not-fixed' 
        ? `Upgrade to version ${finding.fixedVersion}` 
        : undefined,
      location: finding.location,
      cwe: finding.cwe,
      metadata: finding.metadata,
    }));
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
      tool: 'trivy',
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
 * Factory function to create a TrivyScanner instance.
 * 
 * @param {TrivyConfig} config - Configuration for the Trivy scanner
 * @returns {TrivyScanner} Configured TrivyScanner instance
 */
export function createTrivyScanner(config: TrivyConfig): TrivyScanner {
  return new TrivyScanner(config);
}