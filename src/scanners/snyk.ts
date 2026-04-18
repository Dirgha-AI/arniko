import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import { readFile } from 'fs/promises';
import { join } from 'path';
import type { ScanTarget, ScanResult } from '../types/index.js';

interface Vulnerability { id: string; title: string; severity: string; packageName: string; version: string; fixedIn?: string[]; from?: string[]; description?: string; [key: string]: unknown; }
interface SnykIssue { id: string; title: string; severity: string; type?: string; [key: string]: unknown; }
interface SnykMonitorResponse { id?: string; publicId?: string; [key: string]: unknown; }
interface SnykTestResult { ok: boolean; vulnerabilities?: Vulnerability[]; dependencyCount?: number; summary?: string; [key: string]: unknown; }

const execAsync = promisify(exec);

/**
 * Adapter for Snyk vulnerability scanner supporting dependencies, containers, and IaC.
 * Uses both Snyk CLI (preferred for local scans) and REST API v3.
 */
export class SnykScanner {
  private readonly apiKey: string | undefined;
  private readonly orgId: string | undefined;
  private readonly baseUrl: string = 'https://api.snyk.io/rest';
  private readonly apiVersion: string = '2024-01-23';
  private readonly headers: Record<string, string>;

  constructor(config: { apiKey?: string; orgId?: string }) {
    this.apiKey = config.apiKey;
    this.orgId = config.orgId;

    this.headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Snyk-Version': '2024-01-23',
    };

    if (this.apiKey) {
      this.headers['Authorization'] = `token ${this.apiKey}`;
    }
  }

  /**
   * Check if Snyk CLI is installed and available
   * @returns Object containing installation status and version
   */
  async checkInstalled(): Promise<{ installed: boolean; version?: string }> {
    return new Promise((resolve) => {
      const child = spawn('snyk', ['version'], { 
        shell: true,
        stdio: ['ignore', 'pipe', 'pipe'] 
      });
      
      let output = '';
      let errorOutput = '';

      child.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      child.stderr.on('data', (data: Buffer) => {
        errorOutput += data.toString();
      });

      child.on('close', (code: number | null) => {
        if (code === 0 && output) {
          resolve({ 
            installed: true, 
            version: output.trim() 
          });
        } else {
          resolve({ 
            installed: false, 
            version: undefined 
          });
        }
      });

      child.on('error', () => {
        resolve({ installed: false });
      });

      // Timeout after 5 seconds
      setTimeout(() => {
        child.kill();
        resolve({ installed: false });
      }, 5000);
    });
  }

  /**
   * Test a project for vulnerabilities
   * Uses CLI if available, falls back to REST API
   * @param path - Path to project directory or manifest file
   * @returns Vulnerability report with dependencies and summary
   */
  async testProject(path: string): Promise<{
    vulnerabilities: Array<{
      id: string;
      title: string;
      severity: string;
      packageName: string;
      version: string;
      fixedIn?: string[];
      from: string[];
    }>;
    dependencyCount: number;
    summary: string;
  }> {
    // Prefer CLI for local testing (more accurate with local node_modules)
    const cliCheck = await this.checkInstalled();
    
    if (cliCheck.installed) {
      try {
        const { stdout, stderr } = await execAsync(
          `snyk test --json --file="${path}"${this.orgId ? ` --org=${this.orgId}` : ''}`,
          {
            cwd: process.cwd(),
            maxBuffer: 1024 * 1024 * 50, // 50MB buffer for large projects
            timeout: 300000, // 5 minutes timeout
          }
        );

        const result: SnykTestResult = JSON.parse(stdout);
        
        return {
          vulnerabilities: result.vulnerabilities?.map((v) => ({
            id: v.id,
            title: v.title,
            severity: v.severity,
            packageName: v.packageName,
            version: v.version,
            fixedIn: v.fixedIn,
            from: v.from ?? [],
          })) || [],
          dependencyCount: result.dependencyCount || 0,
          summary: result.summary || `Found ${result.vulnerabilities?.length || 0} vulnerabilities`,
        };
      } catch (error: any) {
        // Snyk CLI exits with code 1 when vulnerabilities are found but still outputs valid JSON
        if (error.stdout) {
          try {
            const result: SnykTestResult = JSON.parse(error.stdout);
            return {
              vulnerabilities: result.vulnerabilities?.map((v) => ({
                id: v.id,
                title: v.title,
                severity: v.severity,
                packageName: v.packageName,
                version: v.version,
                fixedIn: v.fixedIn,
                from: v.from ?? [],
              })) || [],
              dependencyCount: result.dependencyCount || 0,
              summary: result.summary || `Found ${result.vulnerabilities?.length || 0} vulnerabilities`,
            };
          } catch (parseError) {
            throw new Error(`Failed to parse Snyk test output: ${parseError}`);
          }
        }
        // If no stdout, try API fallback
      }
    }

    // Fallback to REST API
    if (!this.apiKey) {
      throw new Error('Snyk CLI not installed and no API key provided for API fallback');
    }

    return this.testProjectViaApi(path);
  }

  /**
   * Test project via Snyk REST API v3
   * @private
   */
  private async testProjectViaApi(path: string): Promise<any> {
    const manifestPath = join(path, 'package.json');
    let manifestContent: string;

    try {
      manifestContent = await readFile(manifestPath, 'utf-8');
    } catch (error) {
      throw new Error(`Could not read package.json at ${manifestPath}: ${error}`);
    }

    const orgId = this.orgId || 'default';
    const response = await fetch(
      `${this.baseUrl}/orgs/${orgId}/test/dep-graph?version=${this.apiVersion}`,
      {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify({
          depGraph: {
            schemaVersion: '1.2.0',
            pkgManager: { name: 'npm' },
            pkgs: [{ id: 'app@1.0.0', info: { name: 'app', version: '1.0.0' } }],
            graph: { rootNodeId: 'root-node', nodes: [{ nodeId: 'root-node', pkgId: 'app@1.0.0', deps: [] }] },
          },
          target: { remoteUrl: path },
        }),
      },
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Snyk API error (${response.status}): ${errorText}`);
    }

    const result = await response.json();
    
    return {
      vulnerabilities: result.issues?.vulnerabilities || [],
      dependencyCount: result.dependencyCount || 0,
      summary: result.summary || '',
    };
  }

  /**
   * Register project for continuous monitoring
   * @param path - Path to project directory
   * @returns Monitor response with project ID and URL
   */
  async monitorProject(path: string): Promise<SnykMonitorResponse> {
    const cliCheck = await this.checkInstalled();
    
    if (cliCheck.installed) {
      try {
        const { stdout } = await execAsync(
          `snyk monitor --json --file="${path}"${this.orgId ? ` --org=${this.orgId}` : ''}`,
          {
            cwd: process.cwd(),
            maxBuffer: 1024 * 1024 * 10,
            timeout: 120000,
          }
        );

        return JSON.parse(stdout) as SnykMonitorResponse;
      } catch (error: any) {
        if (error.stdout) {
          return JSON.parse(error.stdout) as SnykMonitorResponse;
        }
        throw new Error(`Snyk monitor CLI failed: ${error.message}`);
      }
    }

    // API Fallback
    if (!this.apiKey) {
      throw new Error('API key required for monitor API');
    }

    const manifestPath = join(path, 'package.json');
    const manifestContent = await readFile(manifestPath, 'utf-8');
    const projectName = path.split('/').pop() || 'unknown-project';

    const response = await fetch(`${this.baseUrl}/monitor/npm`, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify({
        files: {
          target: {
            contents: Buffer.from(manifestContent).toString('base64'),
          },
        },
        target: {
          name: projectName,
        },
        ...(this.orgId && { org: this.orgId }),
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Snyk monitor API error (${response.status}): ${errorText}`);
    }

    return await response.json() as SnykMonitorResponse;
  }

  /**
   * List organization-wide issues
   * @param orgId - Snyk organization ID (overrides constructor orgId if provided)
   * @returns Array of issues across all projects in org
   */
  async listIssues(orgId: string): Promise<SnykIssue[]> {
    if (!this.apiKey) {
      throw new Error('API key required to list organization issues');
    }

    const targetOrg = orgId || this.orgId;
    if (!targetOrg) {
      throw new Error('Organization ID required');
    }

    const response = await fetch(
      `${this.baseUrl}/orgs/${targetOrg}/issues?version=${this.apiVersion}&limit=100`,
      {
        method: 'GET',
        headers: this.headers,
      },
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to list issues (${response.status}): ${errorText}`);
    }

    const data = await response.json();
    // v3 response: { data: [{ attributes: { title, severity, coordinates } }] }
    const items = data.data || data.issues || [];
    return items.map((item: any) => item.attributes ?? item) as SnykIssue[];
  }

  /**
   * Generic scan dispatcher supporting multiple target types
   * @param target - Scan target configuration
   * @returns Standardized scan result
   */
  async run(target: ScanTarget): Promise<ScanResult> {
    const t = target as any;
    const targetPath: string = t.path ?? target.identifier;
    switch (t.type) {
      case 'npm':
      case 'maven':
      case 'gradle':
      case 'pip':
        return this.testProject(targetPath) as unknown as Promise<ScanResult>;
      case 'docker':
      case 'container':
        return this.scanContainer(targetPath);
      case 'iac':
      case 'terraform':
      case 'kubernetes':
      case 'cloudformation':
        return this.scanIaC(targetPath, t.type);
      default:
        return this.testProject(target.identifier) as unknown as Promise<ScanResult>;
    }
  }

  private transformContainerResult(data: any): ScanResult {
    return data as ScanResult;
  }

  /**
   * Scan container image
   * @private
   */
  private async scanContainer(imagePath: string): Promise<ScanResult> {
    const cliCheck = await this.checkInstalled();
    if (!cliCheck.installed) {
      throw new Error('Snyk CLI required for container scanning');
    }

    try {
      const { stdout } = await execAsync(
        `snyk container test ${imagePath} --json${this.orgId ? ` --org=${this.orgId}` : ''}`,
        {
          maxBuffer: 1024 * 1024 * 50,
          timeout: 300000,
        }
      );
      
      return this.transformContainerResult(JSON.parse(stdout));
    } catch (error: any) {
      if (error.stdout) {
        return this.transformContainerResult(JSON.parse(error.stdout));
      }
      throw new Error(`Container scan failed: ${error.message}`);
    }
  }

  /**
   * Scan Infrastructure as Code
   * @private
   */
  private async scanIaC(path: string, type: string): Promise<ScanResult> {
    const cliCheck = await this.checkInstalled();
    if (!cliCheck.installed) {
      throw new Error('Snyk CLI required for IaC scanning');
    }

    try {
      const { stdout } = await execAsync(
        `snyk iac test "${path}" --json` 
      );
      return JSON.parse(stdout);
    } catch { throw new Error(`IaC scan failed for ${path}`); }
  }
}
