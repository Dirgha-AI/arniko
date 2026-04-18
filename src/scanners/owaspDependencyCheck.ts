import { spawn } from 'child_process';
import { randomUUID } from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import { ScanFinding } from '../types/index.js';

interface OWASPConfig {
  path: string;
  format?: 'json' | 'sarif' | 'html';
  suppressionFile?: string;
}

interface OWASPReference {
  source: string;
  url: string;
  name: string;
}

interface OWASPVulnerability {
  source: string;
  name: string;
  severity: string;
  cvssv2?: {
    score: number;
    severity?: string;
  };
  cvssv3?: {
    baseScore: number;
    baseSeverity: string;
  };
  description: string;
  references?: OWASPReference[];
  vulnerableSoftware?: Array<{ software: string; allPreviousVersion: boolean }>;
}

interface OWASPDependency {
  fileName: string;
  filePath: string;
  md5?: string;
  sha1?: string;
  packages?: Array<{ id: string; confidence: string }>;
  vulnerabilities?: OWASPVulnerability[];
}

interface OWASPReport {
  reportSchema: string;
  scanInfo: {
    engineVersion: string;
    dataSource: Array<{ name: string; timestamp: string }>;
  };
  projectInfo: {
    name: string;
    reportDate: string;
    credits: {
      NVD: string;
      NPM: string;
      RETIREJS: string;
      OSSINDEX: string;
    };
  };
  dependencies: OWASPDependency[];
}

export class OWASPDependencyCheckScanner {
  private config: Required<Pick<OWASPConfig, 'path'>> & Omit<OWASPConfig, 'path'>;
  private readonly defaultFormat: 'json' | 'sarif' | 'html' = 'json';

  constructor(config: OWASPConfig) {
    this.config = {
      path: config.path,
      format: config.format || this.defaultFormat,
      suppressionFile: config.suppressionFile
    };
  }

  /**
   * Verify that dependency-check CLI is installed and accessible
   */
  async checkInstalled(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.config.path, ['--version'], {
        shell: true,
        windowsHide: true
      });

      let stderr = '';

      child.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      child.on('close', (code: number | null) => {
        if (code === 0) {
          resolve(true);
        } else {
          reject(new Error(
            `OWASP Dependency Check not installed or not accessible. ` +
            `Exit code: ${code}. Path: ${this.config.path}`
          ));
        }
      });

      child.on('error', (err: Error) => {
        reject(new Error(`Failed to spawn dependency-check: ${err.message}`));
      });
    });
  }

  /**
   * Execute the dependency-check CLI
   */
  private async runCLI(target: string, outputDir: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const args: string[] = [
        '--scan', target,
        '--format', 'JSON',
        '--out', outputDir,
        '--project', path.basename(target)
      ];

      if (this.config.suppressionFile) {
        args.push('--suppression', this.config.suppressionFile);
      }

      // Enable experimental analyzers for comprehensive scanning
      args.push('--enableExperimental');

      const child = spawn(this.config.path, args, {
        shell: true,
        windowsHide: true
      });

      let stderr = '';

      child.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      child.on('close', (code: number | null) => {
        // ODC returns 0 on success, 1 if vulnerabilities found (which is still success for us)
        if (code === 0 || code === 1) {
          resolve();
        } else {
          reject(new Error(
            `Dependency Check CLI failed with exit code ${code}. ` +
            `Stderr: ${stderr || 'No error output'}`
          ));
        }
      });

      child.on('error', (err: Error) => {
        reject(new Error(`Failed to run dependency-check CLI: ${err.message}`));
      });
    });
  }

  /**
   * Parse OWASP JSON report and map to ScanFinding array
   */
  async parseResult(reportPath: string): Promise<ScanFinding[]> {
    try {
      const content = await fs.readFile(reportPath, 'utf-8');
      const report: OWASPReport = JSON.parse(content);
      
      const findings: ScanFinding[] = [];

      if (!report.dependencies || !Array.isArray(report.dependencies)) {
        return findings;
      }

      for (const dependency of report.dependencies) {
        if (!dependency.vulnerabilities || dependency.vulnerabilities.length === 0) {
          continue;
        }

        // Extract package identifier from evidence or filename
        const packageId = dependency.packages?.[0]?.id || 
                         dependency.fileName || 
                         'unknown';

        for (const vuln of dependency.vulnerabilities) {
          // Determine severity from CVSS v3 first, then v2, then raw severity field
          let severity = vuln.severity || 'UNKNOWN';
          if (vuln.cvssv3?.baseSeverity) {
            severity = vuln.cvssv3.baseSeverity;
          } else if (vuln.cvssv2?.severity) {
            severity = vuln.cvssv2.severity;
          }

          // Extract CVSS score
          const cvssScore = vuln.cvssv3?.baseScore || vuln.cvssv2?.score;

          const finding: ScanFinding = {
            id: vuln.name || randomUUID(),
            tool: 'custom',
            severity: this.normalizeSeverity(severity),
            title: vuln.name || 'Dependency Vulnerability',
            description: vuln.description || 'No description available',
            metadata: {
              cve: vuln.name,
              references: this.extractReferences(vuln.references),
              packageName: packageId,
              filePath: dependency.filePath || '',
              cvssScore,
              source: vuln.source || 'NVD',
              fileName: dependency.fileName,
              md5: dependency.md5,
              sha1: dependency.sha1,
              vulnerableSoftware: vuln.vulnerableSoftware?.map((vs: any) => vs.software) || []
            }
          };

          findings.push(finding);
        }
      }

      return findings;
    } catch (error) {
      throw new Error(
        `Failed to parse OWASP Dependency Check report at ${reportPath}: ` +
        `${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Normalize severity strings to standard format
   */
  private normalizeSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const upper = severity.toUpperCase();

    if (upper === 'CRITICAL') return 'critical';
    if (upper === 'HIGH') return 'high';
    if (upper === 'MEDIUM') return 'medium';
    if (upper === 'LOW') return 'low';
    if (upper === 'INFO') return 'info';

    // Handle numeric-like severity strings (e.g., CVSS scores or level numbers)
    const numericValue = parseFloat(severity);
    if (!isNaN(numericValue)) {
      if (numericValue >= 9.0) return 'critical';
      if (numericValue >= 7.0) return 'high';
      if (numericValue >= 4.0) return 'medium';
      if (numericValue >= 2.0) return 'low';
      return 'info';
    }

    return 'info';
  }

  private extractReferences(references: OWASPReference[] | undefined): string[] {
    if (!references) {
      return [];
    }
    return references
      .filter(ref => !!ref.url)
      .map(ref => ref.url);
  }

  async run(target: { identifier: string }): Promise<{ findings: ScanFinding[] }> {
    const findings = await this.parseResult(target.identifier);
    return { findings };
  }
}
