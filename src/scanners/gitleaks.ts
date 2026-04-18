import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import * as path from 'path';
import { ScanFinding, ScanSeverity, ScanTool } from '../types/index.js';

export interface GitLeaksConfig {
  path?: string;
  gitRepo?: string;
  configPath?: string;
}

interface GitLeaksRawFinding {
  RuleID: string;
  Description: string;
  StartLine: number;
  EndLine: number;
  StartColumn?: number;
  EndColumn?: number;
  Match: string;
  Secret: string;
  File: string;
  Commit?: string;
  Author?: string;
  Email?: string;
  Date?: string;
  Message?: string;
  Tags?: string[];
}

interface GitLeaksFindingMetadata {
  endLine: number;
  startColumn?: number;
  endColumn?: number;
  match: string;
  author?: string;
  email?: string;
  date?: string;
  message?: string;
  tags?: string[];
  [key: string]: unknown;
}

interface GitLeaksScanFinding extends Omit<ScanFinding, 'severity' | 'tool'> {
  id: string;
  ruleId: string;
  description: string;
  secret: string;
  file: string;
  line: number;
  commit: string;
  severity: ScanSeverity;
  tool: ScanTool;
  metadata: GitLeaksFindingMetadata;
}

export class GitLeaksScanner {
  private config: GitLeaksConfig;
  private readonly defaultReportPath = '/tmp/gitleaks-report.json';

  constructor(config: GitLeaksConfig = {}) {
    this.config = config;
  }

  /**
   * Check if GitLeaks is installed by running 'gitleaks version'
   */
  async checkInstalled(): Promise<boolean> {
    return new Promise((resolve) => {
      const proc = spawn('gitleaks', ['version']);
      
      let output = '';
      let errorOutput = '';

      proc.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      proc.stderr.on('data', (data: Buffer) => {
        errorOutput += data.toString();
      });

      proc.on('close', (code: number | null) => {
        // GitLeaks version command returns 0 on success
        resolve(code === 0 && (output.toLowerCase().includes('gitleaks') || /^\d+\.\d+\.\d+/.test(output)));
      });

      proc.on('error', () => {
        resolve(false);
      });

      // Timeout after 5 seconds
      setTimeout(() => {
        proc.kill();
        resolve(false);
      }, 5000);
    });
  }

  /**
   * Run GitLeaks CLI to detect secrets
   */
  async runCLI(): Promise<string> {
    const sourcePath = this.config.gitRepo || this.config.path || '.';
    const reportPath = this.defaultReportPath;
    
    const args: string[] = [
      'detect',
      '--source', sourcePath,
      '--report-format', 'json',
      '--report-path', reportPath
    ];

    // Add custom config if provided
    if (this.config.configPath) {
      args.push('--config', this.config.configPath);
    }

    // If path is specified but not as a git repo, add --no-git flag
    if (this.config.path && !this.config.gitRepo) {
      try {
        const isRepo = await this.isGitRepo(sourcePath);
        if (!isRepo) {
          args.push('--no-git');
        }
      } catch {
        // If we can't determine, assume it's not a git repo
        args.push('--no-git');
      }
    }

    return new Promise((resolve, reject) => {
      const proc = spawn('gitleaks', args);
      
      let stderr = '';

      proc.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      proc.on('close', (code: number | null) => {
        // GitLeaks returns exit code 1 when secrets are found (which is expected)
        // Exit code 0 means no secrets found
        // Any other code is an error
        if (code === 0 || code === 1) {
          resolve(reportPath);
        } else {
          reject(new Error(`GitLeaks failed with exit code ${code}: ${stderr || 'Unknown error'}`));
        }
      });

      proc.on('error', (err: Error) => {
        reject(new Error(`Failed to spawn GitLeaks: ${err.message}`));
      });
    });
  }

  /**
   * Parse GitLeaks JSON report and map to ScanFinding format
   */
  async parseResult(reportPath?: string): Promise<GitLeaksScanFinding[]> {
    const targetPath = reportPath || this.defaultReportPath;
    
    try {
      const data = await fs.readFile(targetPath, 'utf-8');
      const rawFindings: GitLeaksRawFinding[] = JSON.parse(data) as GitLeaksRawFinding[];
      
      if (!Array.isArray(rawFindings)) {
        return [];
      }
      
      return rawFindings.map((finding) => this.mapToScanFinding(finding));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        // No report file means no findings (clean scan) or scan failed to create file
        return [];
      }
      if (error instanceof SyntaxError) {
        throw new Error(`Failed to parse GitLeaks report JSON: ${error.message}`);
      }
      throw new Error(`Failed to read GitLeaks report: ${(error as Error).message}`);
    }
  }

  /**
   * Map GitLeaks raw finding to standardized ScanFinding
   */
  private mapToScanFinding(raw: GitLeaksRawFinding): GitLeaksScanFinding {
    return {
      id: raw.RuleID,
      title: raw.Description,
      ruleId: raw.RuleID,
      description: raw.Description,
      secret: this.redactSecret(raw.Secret),
      file: raw.File,
      line: raw.StartLine,
      commit: raw.Commit || 'unknown',
      severity: 'high' as ScanSeverity,
      tool: 'trufflehog' as ScanTool,
      // Extended metadata for additional context
      metadata: {
        endLine: raw.EndLine,
        startColumn: raw.StartColumn,
        endColumn: raw.EndColumn,
        match: raw.Match,
        author: raw.Author,
        email: raw.Email,
        date: raw.Date,
        message: raw.Message,
        tags: raw.Tags
      }
    };
  }

  /**
   * Redact secret for security (show first 2 and last 2 chars only, or [REDACTED] if short)
   */
  private redactSecret(secret: string): string {
    if (!secret) return '[REDACTED]';
    if (secret.length <= 8) return '[REDACTED]';
    
    const firstTwo = secret.substring(0, 2);
    const lastTwo = secret.substring(secret.length - 2);
    const middleLength = secret.length - 4;
    const asterisks = '*'.repeat(Math.min(middleLength, 8)); // Cap asterisks at 8
    
    return `${firstTwo}${asterisks}${lastTwo}`;
  }

  /**
   * Main execution method - runs the full scan pipeline
   */
  async run(target?: string): Promise<GitLeaksScanFinding[]> {
    // Update config if target is provided for this run
    if (target) {
      const isRepo = await this.isGitRepo(target);
      if (isRepo) {
        this.config.gitRepo = target;
        this.config.path = undefined;
      } else {
        this.config.path = target;
        this.config.gitRepo = undefined;
      }
    }

    const isInstalled = await this.checkInstalled();
    if (!isInstalled) {
      throw new Error('GitLeaks is not installed. Please install it: https://github.com/gitleaks/gitleaks#installing');
    }

    try {
      const reportPath = await this.runCLI();
      const findings = await this.parseResult(reportPath);
      
      // Optional: Clean up report file after parsing
      try {
        await fs.unlink(reportPath);
      } catch {
        // Ignore cleanup errors
      }
      
      return findings;
    } catch (error) {
      throw new Error(`GitLeaks scan failed: ${(error as Error).message}`);
    }
  }

  /**
   * Check if path is a git repository
   */
  private async isGitRepo(targetPath: string): Promise<boolean> {
    try {
      const gitPath = path.join(targetPath, '.git');
      const stat = await fs.stat(gitPath);
      return stat.isDirectory();
    } catch {
      return false;
    }
  }

  /**
   * Simulate a scan for testing/demo purposes without requiring GitLeaks installation
   */
  async simulateScan(): Promise<GitLeaksScanFinding[]> {
    const mockFindings: GitLeaksRawFinding[] = [
      {
        RuleID: 'aws-access-key-id',
        Description: 'AWS Access Key ID',
        StartLine: 15,
        EndLine: 15,
        StartColumn: 10,
        EndColumn: 30,
        Match: 'AKIAIOSFODNN7EXAMPLE',
        Secret: 'AKIAIOSFODNN7EXAMPLE',
        File: 'src/config/credentials.yml',
        Commit: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
        Author: 'Developer One',
        Email: 'dev1@example.com',
        Date: '2023-12-01T10:30:00Z',
        Message: 'Add AWS configuration',
        Tags: ['aws', 'key', 'access-key-id']
      },
      {
        RuleID: 'generic-api-key',
        Description: 'Generic API Key',
        StartLine: 42,
        EndLine: 42,
        StartColumn: 20,
        EndColumn: 60,
        Match: 'api_key=sk-1234567890abcdef',
        Secret: 'sk-1234567890abcdef1234567890abcdef12345678',
        File: 'src/services/payment.ts',
        Commit: 'b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1',
        Author: 'Developer Two',
        Email: 'dev2@example.com',
        Date: '2023-12-02T14:22:00Z',
        Message: 'Integrate payment API',
        Tags: ['api', 'key', 'generic']
      },
      {
        RuleID: 'private-key',
        Description: 'Private Key',
        StartLine: 1,
        EndLine: 27,
        StartColumn: 1,
        EndColumn: 30,
        Match: '-----BEGIN RSA PRIVATE KEY-----',
        Secret: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgwKVPSmwaFkYLv\n...\n-----END RSA PRIVATE KEY-----',
        File: 'certs/private.pem',
        Commit: 'c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2',
        Author: 'DevOps Engineer',
        Email: 'devops@example.com',
        Date: '2023-12-03T09:15:00Z',
        Message: 'Add SSL certificates',
        Tags: ['key', 'private', 'rsa']
      },
      {
        RuleID: 'slack-webhook',
        Description: 'Slack Webhook',
        StartLine: 8,
        EndLine: 8,
        StartColumn: 25,
        EndColumn: 85,
        Match: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
        Secret: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
        File: 'config/notifications.json',
        Commit: 'd4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3',
        Author: 'Developer Three',
        Email: 'dev3@example.com',
        Date: '2023-12-04T16:45:00Z',
        Message: 'Configure Slack notifications',
        Tags: ['slack', 'webhook']
      }
    ];

    // Simulate processing delay
    await new Promise<void>(resolve => setTimeout(resolve, 800));
    
    return mockFindings.map(finding => this.mapToScanFinding(finding));
  }
}