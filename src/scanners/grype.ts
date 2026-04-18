import { spawn } from 'child_process';
import type { ScanFinding } from '../types/index.js';

/**
 * Internal type definitions matching Grype JSON output structure
 */
interface GrypeVulnerability {
  id: string;
  severity: string;
  fix?: {
    versions?: string[];
    state?: string;
  };
}

interface GrypeArtifact {
  name: string;
  version: string;
  type?: string;
  locations?: Array<{ path: string }>;
}

interface GrypeMatch {
  vulnerability: GrypeVulnerability;
  artifact: GrypeArtifact;
}

interface GrypeJsonOutput {
  matches: GrypeMatch[];
}

export interface GrypeScannerConfig {
  target: string;
  failOnSeverity?: string;
}

export class GrypeScanner {
  private config: GrypeScannerConfig;

  constructor(config: GrypeScannerConfig) {
    this.config = config;
  }

  /**
   * Checks if Grype CLI is installed by spawning 'grype version'
   * @returns Promise<boolean> Resolves true if grype is available
   * @throws Error if grype is not installed or not in PATH
   */
  async checkInstalled(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const grypeProcess = spawn('grype', ['version']);
      
      let stderr = '';

      grypeProcess.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      grypeProcess.on('error', (error) => {
        reject(new Error(`Grype is not installed or not available in PATH: ${error.message}`));
      });

      grypeProcess.on('close', (code) => {
        if (code === 0) {
          resolve(true);
        } else {
          reject(new Error(`Grype version check failed with exit code ${code}: ${stderr}`));
        }
      });
    });
  }

  /**
   * Runs Grype CLI against the target with JSON output
   * Executes: grype <target> -o json [--fail-on <severity>]
   * @param target Optional target override (container image, directory, or SBOM path)
   * @returns Promise<string> Raw JSON output from Grype
   */
  async runCLI(target?: string): Promise<string> {
    const scanTarget = target || this.config.target;
    
    if (!scanTarget) {
      throw new Error('No scan target specified. Provide target in constructor or run() method.');
    }

    return new Promise((resolve, reject) => {
      const args: string[] = [scanTarget, '-o', 'json'];
      
      if (this.config.failOnSeverity) {
        args.push('--fail-on', this.config.failOnSeverity);
      }

      const grypeProcess = spawn('grype', args);
      
      let stdout = '';
      let stderr = '';

      grypeProcess.stdout.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      grypeProcess.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      grypeProcess.on('error', (error) => {
        reject(new Error(`Failed to spawn Grype process: ${error.message}`));
      });

      grypeProcess.on('close', (code) => {
        // Grype exits with non-zero when vulnerabilities match fail-on severity
        // but still outputs valid JSON to stdout
        if (stdout && stdout.trim().startsWith('{')) {
          resolve(stdout);
        } else {
          reject(new Error(`Grype scan failed (exit code ${code}): ${stderr || 'No output received'}`));
        }
      });
    });
  }

  /**
   * Parses Grype JSON output and maps matches to ScanFinding array
   * Maps fields: vulnerability.id, vulnerability.severity, artifact.name, 
   * artifact.version, vulnerability.fix.versions
   * @param rawOutput Raw JSON string from Grype CLI
   * @returns ScanFinding[] Array of mapped vulnerability findings
   */
  parseResult(rawOutput: string): ScanFinding[] {
    try {
      const parsed: GrypeJsonOutput = JSON.parse(rawOutput);
      
      if (!parsed.matches || !Array.isArray(parsed.matches)) {
        return [];
      }

      return parsed.matches.map((match): any => ({
        id: match.vulnerability.id,
        severity: (match.vulnerability.severity || 'info').toLowerCase() as any,
        packageName: match.artifact.name,
        packageVersion: match.artifact.version,
        fixVersions: match.vulnerability.fix?.versions || [],
        artifactType: match.artifact.type,
        fixState: match.vulnerability.fix?.state
      }));
    } catch (error) {
      throw new Error(`Failed to parse Grype JSON output: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Main execution method - runs full scan pipeline
   * Checks installation, runs CLI, and parses results
   * @param target Optional target override (defaults to constructor config)
   * @returns Promise<ScanFinding[]> Array of vulnerability findings
   */
  async run(target?: string): Promise<ScanFinding[]> {
    await this.checkInstalled();
    const rawOutput = await this.runCLI(target);
    return this.parseResult(rawOutput);
  }

  /**
   * Simulates a scan for testing/development purposes
   * Returns mock data matching the Grype output structure
   * @returns ScanFinding[] Mock vulnerability findings
   */
  simulateScan(): any[] {
    return [
      {
        id: 'CVE-2023-38408',
        severity: 'critical',
        packageName: 'openssl',
        packageVersion: '1.1.1n-0+deb11u4',
        fixVersions: ['1.1.1n-0+deb11u5'],
        artifactType: 'deb',
        fixState: 'fixed'
      },
      {
        id: 'CVE-2022-42889',
        severity: 'high',
        packageName: 'commons-text',
        packageVersion: '1.9',
        fixVersions: ['1.10.0'],
        artifactType: 'java-archive',
        fixState: 'fixed'
      },
      {
        id: 'GHSA-7rjr-3q55-3vgr',
        severity: 'medium',
        packageName: 'lodash',
        packageVersion: '4.17.20',
        fixVersions: ['4.17.21'],
        artifactType: 'npm',
        fixState: 'fixed'
      },
      {
        id: 'CVE-2023-29383',
        severity: 'low',
        packageName: 'shadow',
        packageVersion: '1:4.8.1-1',
        fixVersions: [],
        artifactType: 'deb',
        fixState: 'not-fixed'
      }
    ];
  }
}