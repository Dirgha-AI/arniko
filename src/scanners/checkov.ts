import { spawn } from 'child_process';
import type { ScanFinding, ScanSeverity } from '../types/index.js';

export interface CheckovConfig {
  path: string;
  framework?: 'terraform' | 'cloudformation' | 'kubernetes' | 'dockerfile' | 'all';
}

interface CheckovCheck {
  check_id: string;
  check_name: string;
  check_result: {
    result: 'PASSED' | 'FAILED';
    evaluated_keys?: string[];
  };
  file_path: string;
  file_abs_path: string;
  repo_file_path: string;
  resource: string;
  guidelines?: string;
  description?: string;
  severity?: string;
}

interface CheckovOutput {
  passed_checks: CheckovCheck[];
  failed_checks: CheckovCheck[];
  summary?: {
    passed: number;
    failed: number;
    skipped: number;
    parsing_errors: number;
    checkov_version?: string;
  };
}

export class CheckovScanner {
  private config: CheckovConfig;

  constructor(config: CheckovConfig) {
    this.config = config;
  }

  /**
   * Verifies that Checkov is installed and available in PATH
   */
  async checkInstalled(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const versionProc = spawn('checkov', ['--version'], {
        cwd: this.config.path
      });

      let errorOutput = '';

      versionProc.stderr.on('data', (data: Buffer) => {
        errorOutput += data.toString();
      });

      versionProc.on('close', (code: number | null) => {
        resolve(code === 0);
      });

      versionProc.on('error', () => {
        resolve(false);
      });
    });
  }

  /**
   * Main execution method that runs the scan and returns parsed findings
   */
  async run(target: string): Promise<ScanFinding[]> {
    const installed = await this.checkInstalled();
    if (!installed) {
      throw new Error('Checkov is not installed. Install with: pip install checkov');
    }
    const rawOutput = await this.runCLI(target);
    return this.parseResult(rawOutput);
  }

  /**
   * Executes Checkov CLI with JSON output format
   */
  async runCLI(target: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const args: string[] = [
        '-d', target,
        '--output', 'json',
        '--compact' // Reduce output noise
      ];

      if (this.config.framework && this.config.framework !== 'all') {
        args.push('--framework', this.config.framework);
      }

      // Add soft-fail to ensure we get JSON output even if checks fail
      args.push('--soft-fail');

      const proc = spawn('checkov', args, {
        cwd: this.config.path,
        env: {
          ...process.env,
          // Ensure Python output is not buffered
          PYTHONUNBUFFERED: '1'
        }
      });

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      proc.on('close', (code: number | null) => {
        // Checkov returns exit code 0 with --soft-fail, or 1 without it if findings exist
        // We accept both 0 and 1 as valid if we have parseable JSON output
        if (code === 0 || code === 1) {
          if (stdout.trim().length === 0) {
            reject(new Error(`Checkov produced no output. Stderr: ${stderr}`));
          } else {
            resolve(stdout);
          }
        } else {
          reject(new Error(
            `Checkov scan failed with exit code ${code}. ` +
            `Stderr: ${stderr || 'No error output'}`
          ));
        }
      });

      proc.on('error', (error: Error) => {
        reject(new Error(`Failed to execute Checkov: ${error.message}`));
      });
    });
  }

  /**
   * Parses Checkov JSON output into standardized ScanFinding array
   */
  parseResult(jsonOutput: string): ScanFinding[] {
    try {
      // Checkov might output multiple JSON objects or have leading/trailing whitespace
      const cleanedOutput = jsonOutput.trim();
      
      // Handle case where output might contain multiple JSON objects (rare but possible)
      // We take the first valid JSON object that looks like Checkov output
      let parsed: CheckovOutput;
      
      try {
        parsed = JSON.parse(cleanedOutput) as CheckovOutput;
      } catch (parseError) {
        // Try to extract JSON from mixed output (in case of logging prefix)
        const jsonMatch = cleanedOutput.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          parsed = JSON.parse(jsonMatch[0]) as CheckovOutput;
        } else {
          throw parseError;
        }
      }

      const findings: any[] = [];

      // Process passed checks
      if (Array.isArray(parsed.passed_checks)) {
        for (const check of parsed.passed_checks) {
          findings.push(this.mapCheckToFinding(check, 'passed'));
        }
      }

      // Process failed checks
      if (Array.isArray(parsed.failed_checks)) {
        for (const check of parsed.failed_checks) {
          findings.push(this.mapCheckToFinding(check, 'failed'));
        }
      }

      return findings;
    } catch (error) {
      throw new Error(
        `Failed to parse Checkov JSON output: ${error instanceof Error ? error.message : 'Unknown parsing error'}. ` +
        `Raw output preview: ${jsonOutput.substring(0, 200)}...`
      );
    }
  }

  /**
   * Maps a single Checkov check result to ScanFinding format
   */
  private mapCheckToFinding(check: CheckovCheck, status: 'passed' | 'failed'): any {
    return {
      check_id: check.check_id,
      check_type: status,
      file_path: check.file_path || check.file_abs_path || check.repo_file_path || 'unknown',
      resource: check.resource || 'unknown',
      guideline: check.guidelines || check.description || 'No guideline available',
      severity: this.normalizeSeverity(check.severity, status),
      description: check.check_name || 'No description available',
      // Additional metadata that might be useful
      metadata: {
        evaluated_keys: check.check_result?.evaluated_keys || [],
        check_result: check.check_result?.result
      }
    };
  }

  /**
   * Normalizes severity levels, defaulting based on pass/fail status if not provided
   */
  private normalizeSeverity(severity: string | undefined, status: 'passed' | 'failed'): string {
    if (severity) {
      return severity.toLowerCase();
    }
    // Default severity based on status
    return status === 'failed' ? 'medium' : 'info';
  }

  /**
   * Returns simulated scan results for testing/demo purposes
   */
  simulateScan(): any[] {
    const mockFindings: any[] = [
      {
        check_id: 'CKV_AWS_19',
        check_type: 'failed',
        file_path: 'terraform/aws/s3.tf',
        resource: 'aws_s3_bucket.data_bucket',
        guideline: 'Ensure all data stored in the S3 bucket is securely encrypted at rest. ' +
                  'Use AES256 or aws:kms for server-side encryption.',
        severity: 'high',
        description: 'S3 Bucket does not have server-side encryption enabled',
        metadata: {
          evaluated_keys: ['server_side_encryption_configuration'],
          check_result: 'FAILED'
        }
      },
      {
        check_id: 'CKV_AWS_18',
        check_type: 'passed',
        file_path: 'terraform/aws/s3.tf',
        resource: 'aws_s3_bucket.data_bucket',
        guideline: 'Ensure S3 bucket logging is enabled for security auditing purposes.',
        severity: 'medium',
        description: 'S3 Bucket has access logging enabled',
        metadata: {
          evaluated_keys: ['logging'],
          check_result: 'PASSED'
        }
      },
      {
        check_id: 'CKV_AWS_23',
        check_type: 'failed',
        file_path: 'terraform/aws/security_groups.tf',
        resource: 'aws_security_group.allow_ssh',
        guideline: 'Ensure every security group has a description to improve documentation and auditing.',
        severity: 'low',
        description: 'Security group does not have a description',
        metadata: {
          evaluated_keys: ['description'],
          check_result: 'FAILED'
        }
      },
      {
        check_id: 'CKV_DOCKER_2',
        check_type: 'failed',
        file_path: 'Dockerfile',
        resource: 'FROM',
        guideline: 'Ensure that HEALTHCHECK instructions have been added to container images. ' +
                  'This allows Docker to check if the container is still working properly.',
        severity: 'medium',
        description: 'Ensure that HEALTHCHECK instructions have been added to container images',
        metadata: {
          evaluated_keys: ['HEALTHCHECK'],
          check_result: 'FAILED'
        }
      },
      {
        check_id: 'CKV_K8S_21',
        check_type: 'passed',
        file_path: 'k8s/deployment.yaml',
        resource: 'Deployment.app',
        guideline: 'The default namespace should not be used for production workloads.',
        severity: 'low',
        description: 'Default namespace is not used',
        metadata: {
          evaluated_keys: ['metadata.namespace'],
          check_result: 'PASSED'
        }
      }
    ];

    return mockFindings;
  }
}