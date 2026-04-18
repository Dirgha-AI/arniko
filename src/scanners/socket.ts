import { promises as fs } from 'fs';
import * as path from 'path';
import type { ScanTarget, ScanResult } from '../types/index.js';

interface SocketScannerConfig { apiKey?: string; endpoint?: string; timeout?: number; [key: string]: unknown; }
interface Score { overall: number; license?: number; quality: number; maintenance: number; vulnerability: number; supply_chain?: number; [key: string]: unknown; }
interface Alert { type: string; severity?: string; message?: string; [key: string]: unknown; }
interface Issue { id?: string; type?: string; severity: string; message?: string; [key: string]: unknown; }
interface PackageAnalysis { name?: string; version?: string; score: Score; alerts: Alert[]; dependencies?: string[]; [key: string]: unknown; }
interface LockfileAnalysis { packages: PackageAnalysis[]; summary: { totalPackages: number; riskScore: number; criticalAlerts?: number; highAlerts?: number; [key: string]: unknown }; [key: string]: unknown; }

/**
 * Socket.dev npm supply chain security scanner adapter.
 * Analyzes npm packages for suspicious behavior including install scripts,
 * network access, filesystem access, and obfuscated code.
 */
export class SocketScanner {
  private readonly apiKey: string | undefined;
  private readonly endpoint: string;
  private readonly headers: Record<string, string>;

  constructor(config: SocketScannerConfig = {}) {
    this.apiKey = config.apiKey;
    this.endpoint = config.endpoint || 'https://api.socket.dev/v0';
    
    this.headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
    
    if (this.apiKey) {
      this.headers['Authorization'] = `Bearer ${this.apiKey}`;
    }
  }

  /**
   * Analyze a specific npm package version for security risks.
   * GET /npm/{package}/{version}/score
   */
  async analyzePackage(packageName: string, version?: string): Promise<PackageAnalysis> {
    const encodedPackage = encodeURIComponent(packageName);
    const versionPath = version ? `/${encodeURIComponent(version)}` : '';
    const url = `${this.endpoint}/npm/${encodedPackage}${versionPath}/score`;

    const response = await fetch(url, {
      method: 'GET',
      headers: this.headers,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Socket API error ${response.status}: ${errorText}`);
    }

    const data = await response.json();
    
    return {
      score: {
        overall: data.score?.overall ?? 0,
        supply_chain: data.score?.supply_chain ?? 0,
        quality: data.score?.quality ?? 0,
        maintenance: data.score?.maintenance ?? 0,
        vulnerability: data.score?.vulnerability ?? 0,
      },
      alerts: (data.alerts || []).map((alert: any) => ({
        type: alert.type,
        severity: alert.severity,
        description: alert.description,
        url: alert.url,
      })),
    };
  }

  /**
   * Upload and analyze a lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml).
   * POST /report/upload
   */
  async analyzeLockfile(lockfilePath: string): Promise<LockfileAnalysis> {
    const content = await fs.readFile(lockfilePath, 'utf-8');
    const filename = path.basename(lockfilePath);
    
    // Determine lockfile type for the API
    let lockfileType: string;
    if (filename === 'package-lock.json') {
      lockfileType = 'npm';
    } else if (filename === 'yarn.lock') {
      lockfileType = 'yarn';
    } else if (filename === 'pnpm-lock.yaml') {
      lockfileType = 'pnpm';
    } else {
      throw new Error(`Unsupported lockfile format: ${filename}. Expected package-lock.json, yarn.lock, or pnpm-lock.yaml`);
    }

    const url = `${this.endpoint}/report/upload`;
    
    // Construct multipart/form-data manually for native fetch compatibility
    const boundary = `----SocketFormBoundary${Math.random().toString(36).substring(2)}`;
    const formDataParts = [
      `--${boundary}`,
      `Content-Disposition: form-data; name="file"; filename="${filename}"`,
      `Content-Type: ${filename.endsWith('.yaml') ? 'text/yaml' : 'application/json'}`,
      '',
      content,
      `--${boundary}--`,
      ''
    ];
    
    const body = formDataParts.join('\r\n');

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        ...this.headers,
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
      },
      body,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Socket API error ${response.status}: ${errorText}`);
    }

    const data = await response.json();
    
    return {
      packages: (data.packages || []).map((pkg: any) => ({
        name: pkg.name,
        version: pkg.version,
        score: {
          overall: pkg.score?.overall ?? 0,
          supply_chain: pkg.score?.supply_chain ?? 0,
          quality: pkg.score?.quality ?? 0,
          maintenance: pkg.score?.maintenance ?? 0,
          vulnerability: pkg.score?.vulnerability ?? 0,
        },
        alerts: (pkg.alerts || []).map((alert: any) => ({
          type: alert.type,
          severity: alert.severity,
          description: alert.description,
          url: alert.url,
        })),
        dependencies: pkg.dependencies || [],
      })),
      summary: {
        totalPackages: data.summary?.totalPackages ?? 0,
        directDependencies: data.summary?.directDependencies ?? 0,
        transitiveDependencies: data.summary?.transitiveDependencies ?? 0,
        riskScore: data.summary?.riskScore ?? 0,
        criticalAlerts: data.summary?.criticalAlerts ?? 0,
        highAlerts: data.summary?.highAlerts ?? 0,
      },
    };
  }

  /**
   * Get known issues and CVEs for a package.
   * GET /npm/{package}/issues
   */
  async getIssues(packageName: string): Promise<Issue[]> {
    const encodedPackage = encodeURIComponent(packageName);
    const url = `${this.endpoint}/npm/${encodedPackage}/issues`;

    const response = await fetch(url, {
      method: 'GET',
      headers: this.headers,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Socket API error ${response.status}: ${errorText}`);
    }

    const data = await response.json();
    
    return (data.issues || []).map((issue: any) => ({
      id: issue.id,
      type: issue.type,
      severity: issue.severity,
      description: issue.description,
      cve: issue.cve,
      url: issue.url,
      fixedIn: issue.fixedIn,
    }));
  }

  /**
   * Run a comprehensive scan on a target directory.
   * Analyzes package.json + lockfile and returns full dependency tree analysis.
   */
  async run(target: ScanTarget): Promise<ScanResult> {
    const t = target as any;
    const targetPath: string = t.path ?? target.identifier;
    const includeDevDependencies: boolean = t.includeDevDependencies ?? true;
    
    // Read and parse package.json
    const packageJsonPath = path.join(targetPath, 'package.json');
    let packageJson: any;
    try {
      const content = await fs.readFile(packageJsonPath, 'utf-8');
      packageJson = JSON.parse(content);
    } catch (error) {
      throw new Error(`Failed to read package.json at ${packageJsonPath}: ${error}`);
    }
    
    // Locate lockfile
    const lockfileCandidates = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'];
    let lockfilePath: string | null = null;
    
    for (const filename of lockfileCandidates) {
      const fullPath = path.join(targetPath, filename);
      try {
        await fs.access(fullPath);
        lockfilePath = fullPath;
        break;
      } catch {
        continue;
      }
    }
    
    if (!lockfilePath) {
      throw new Error('No lockfile found. Expected package-lock.json, yarn.lock, or pnpm-lock.yaml in ' + targetPath);
    }
    
    // Analyze lockfile
    const lockfileAnalysis = await this.analyzeLockfile(lockfilePath);
    
    // Fetch issues for all packages (with concurrency limit to avoid rate limits)
    const concurrencyLimit = 5;
    const issues: Array<{ package: string; version: string; issues: Issue[] }> = [];
    
    for (let i = 0; i < lockfileAnalysis.packages.length; i += concurrencyLimit) {
      const batch = lockfileAnalysis.packages.slice(i, i + concurrencyLimit);
      const batchResults = await Promise.all(
        batch.map(async (pkg) => {
          try {
            const pkgIssues = await this.getIssues(pkg.name ?? '');
            return {
              package: pkg.name ?? '',
              version: pkg.version ?? '',
              issues: pkgIssues,
            };
          } catch (error) {
            // Continue if individual package issue fetch fails
            return {
              package: pkg.name ?? '',
              version: pkg.version ?? '',
              issues: [],
            };
          }
        })
      );
      issues.push(...batchResults);
    }
    
    // Calculate aggregate statistics
    const criticalIssues = issues.reduce((sum, pkg) => 
      sum + pkg.issues.filter(i => i.severity === 'critical').length, 0
    );
    
    const supplyChainRisks = lockfileAnalysis.packages.reduce((sum, pkg) => {
      const hasSupplyChainAlert = pkg.alerts.some(a => 
        ['install_script', 'network_access', 'filesystem_access', 'obfuscated_code', 'typosquatting']
          .includes(a.type)
      );
      return sum + (hasSupplyChainAlert ? 1 : 0);
    }, 0);
    
    return {
      path: targetPath,
      manifest: {
        name: packageJson.name,
        version: packageJson.version,
        dependencies: packageJson.dependencies || {},
        devDependencies: includeDevDependencies ? packageJson.devDependencies || {} : {},
      },
      lockfileAnalysis,
      issues: issues.filter(i => i.issues.length > 0),
      summary: {
        totalPackages: lockfileAnalysis.summary.totalPackages,
        riskScore: lockfileAnalysis.summary.riskScore,
        criticalIssues,
        supplyChainRisks,
      },
    } as unknown as ScanResult;
  }

  /**
   * Simulate a scan with common npm supply chain issues.
   * Useful for testing and development without API calls.
   */
  simulateScan(): ScanResult {
    const mockPackages = [
      {
        name: 'typosquat-lodash',
        version: '4.17.21',
        score: {
          overall: 12,
          supply_chain: 5,
          quality: 30,
          maintenance: 25,
          vulnerability: 15,
        },
        alerts: [
          {
            type: 'typosquatting',
            severity: 'critical' as const,
            description: 'Package name similar to popular package "lodash" (typosquatting attack)',
            url: 'https://socket.dev/alerts/typosquatting',
          },
          {
            type: 'install_script',
            severity: 'critical' as const,
            description: 'Install script executes shell commands during npm install',
            url: 'https://socket.dev/alerts/install-script',
          },
        ],
        dependencies: [],
      },
      {
        name: 'network-beacon',
        version: '1.2.3',
        score: {
          overall: 28,
          supply_chain: 15,
          quality: 45,
          maintenance: 60,
          vulnerability: 25,
        },
        alerts: [
          {
            type: 'network_access',
            severity: 'high' as const,
            description: 'Package makes network requests to unknown external servers',
            url: 'https://socket.dev/alerts/network-access',
          },
          {
            type: 'filesystem_access',
            severity: 'high' as const,
            description: 'Package reads sensitive files: ~/.npmrc, ~/.ssh/id_rsa',
            url: 'https://socket.dev/alerts/filesystem-access',
          },
        ],
        dependencies: ['node-fetch'],
      },
      {
        name: 'obfuscated-miner',
        version: '2.0.0',
        score: {
          overall: 18,
          supply_chain: 10,
          quality: 20,
          maintenance: 40,
          vulnerability: 30,
        },
        alerts: [
          {
            type: 'obfuscated_code',
            severity: 'critical' as const,
            description: 'Heavily obfuscated JavaScript detected (possible malware)',
            url: 'https://socket.dev/alerts/obfuscated-code',
          },
          {
            type: 'eval_usage',
            severity: 'high' as const,
            description: 'Dynamic code execution via eval() detected',
            url: 'https://socket.dev/alerts/eval-usage',
          },
          {
            type: 'cryptomining',
            severity: 'critical' as const,
            description: 'Cryptocurrency mining code detected',
            url: 'https://socket.dev/alerts/cryptomining',
          },
        ],
        dependencies: [],
      },
      {
        name: 'legitimate-package',
        version: '3.1.4',
        score: {
          overall: 85,
          supply_chain: 90,
          quality: 88,
          maintenance: 80,
          vulnerability: 95,
        },
        alerts: [],
        dependencies: ['obfuscated-miner'], // Transitive risk
      },
    ];

    return {
      path: '/mock/project/path',
      manifest: {
        name: 'vulnerable-app',
        version: '1.0.0',
        dependencies: {
          'typosquat-lodash': '^4.17.21',
          'network-beacon': '^1.2.0',
          'legitimate-package': '^3.1.0',
        },
        devDependencies: {
          'obfuscated-miner': '^2.0.0',
        },
      },
      lockfileAnalysis: {
        packages: mockPackages,
        summary: {
          totalPackages: 6,
          directDependencies: 4,
          transitiveDependencies: 2,
          riskScore: 35,
          criticalAlerts: 3,
          highAlerts: 4,
        },
      },
      issues: [
        {
          package: 'typosquat-lodash',
          version: '4.17.21',
          issues: [
            {
              id: 'CVE-2024-0001',
              type: 'cve',
              severity: 'critical',
              description: 'Malicious package executing arbitrary code on install',
              cve: 'CVE-2024-0001',
              url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-0001',
            },
          ],
        },
        {
          package: 'network-beacon',
          version: '1.2.3',
          issues: [
            {
              id: 'SOCKET-SUPPLY-001',
              type: 'supply_chain',
              severity: 'high',
              description: 'Known data exfiltration package',
              url: 'https://socket.dev/issues/SOCKET-SUPPLY-001',
              fixedIn: '1.2.4',
            },
          ],
        },
      ],
      summary: {
        totalPackages: 6,
        riskScore: 35,
        criticalIssues: 2,
        supplyChainRisks: 4,
      },
    } as unknown as ScanResult;
  }
}