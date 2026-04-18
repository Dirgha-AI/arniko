import { createHash } from 'crypto';
import { spawn } from 'child_process';
import { readFile, readdir, readlink } from 'fs/promises';
import { join } from 'path';

/**
 * Manifest for a verified binary scanner
 */
export interface BinaryManifest {
  name: string;
  expectedHash: string;
  version: string;
  lastVerified: Date;
}

/**
 * Alert generated when supply chain anomaly detected
 */
export interface SupplyChainAlert {
  type: 'binary_tampered' | 'unexpected_network' | 'unexpected_file_write' | 'version_mismatch' | 'unsigned_package';
  severity: 'critical' | 'high' | 'medium';
  scanner: string;
  details: string;
  timestamp: Date;
}

/**
 * Guards against supply chain attacks including compromised scanners and poisoned dependencies.
 * Defends specifically against Mercor/LiteLLM attack patterns.
 */
export class SupplyChainGuard {
  private manifests: Map<string, BinaryManifest> = new Map();
  private alerts: SupplyChainAlert[] = [];
  private readonly knownScanners = ['trivy', 'semgrep', 'trufflehog', 'gitleaks', 'bandit', 'snyk', 'grype', 'checkov', 'codeql', 'deepteam', 'promptfoo'];
  private readonly allowedHosts = new Set(['127.0.0.1', '0.0.0.0', '::1', 'localhost']);

  private async which(binary: string): Promise<string | null> {
    return new Promise((resolve) => {
      const proc = spawn('which', [binary], { stdio: ['ignore', 'pipe', 'ignore'] });
      let path = '';
      proc.stdout.on('data', (data) => path += data.toString());
      proc.on('close', (code) => resolve(code === 0 ? path.trim() : null));
    });
  }

  private async computeHash(path: string): Promise<string> {
    const data = await readFile(path);
    return createHash('sha256').update(data).digest('hex');
  }

  private emitAlert(alert: SupplyChainAlert): void {
    this.alerts.push(alert);
  }

  private isLocalhost(ipHex: string): boolean {
    const ip = this.parseHexIp(ipHex);
    return this.allowedHosts.has(ip) || ip.startsWith('127.') || ip === '0.0.0.0';
  }

  private parseHexIp(hex: string): string {
    const parts = hex.match(/.{2}/g)?.reverse() || [];
    return parts.map(p => parseInt(p, 16)).join('.');
  }

  /**
   * Verify scanner binary integrity before execution
   * @param binaryName - Name of the binary to verify
   * @returns Verification result with computed hash
   */
  async verifyBinary(binaryName: string): Promise<{ valid: boolean; hash: string; expectedHash?: string }> {
    const path = await this.which(binaryName);
    if (!path) {
      this.emitAlert({
        type: 'binary_tampered',
        severity: 'critical',
        scanner: binaryName,
        details: `Binary ${binaryName} not found in PATH`,
        timestamp: new Date()
      });
      return { valid: false, hash: '' };
    }
    
    const hash = await this.computeHash(path);
    const manifest = this.manifests.get(binaryName);
    
    if (!manifest) {
      return { valid: false, hash, expectedHash: undefined };
    }
    
    if (hash !== manifest.expectedHash) {
      this.emitAlert({
        type: 'binary_tampered',
        severity: 'critical',
        scanner: binaryName,
        details: `Hash mismatch: expected ${manifest.expectedHash}, got ${hash}`,
        timestamp: new Date()
      });
      return { valid: false, hash, expectedHash: manifest.expectedHash };
    }
    
    manifest.lastVerified = new Date();
    return { valid: true, hash, expectedHash: manifest.expectedHash };
  }

  /**
   * Register a known-good binary hash
   * @param name - Binary name
   * @param hash - Expected SHA-256 hash
   * @param version - Binary version
   */
  registerBinary(name: string, hash: string, version: string): void {
    this.manifests.set(name, {
      name,
      expectedHash: hash,
      version,
      lastVerified: new Date()
    });
  }

  /**
   * Auto-discover and register all Arniko scanner binaries
   * @returns Array of discovered manifests
   */
  async discoverScanners(): Promise<BinaryManifest[]> {
    const discovered: BinaryManifest[] = [];
    for (const scanner of this.knownScanners) {
      const path = await this.which(scanner);
      if (path) {
        const hash = await this.computeHash(path);
        const manifest: BinaryManifest = {
          name: scanner,
          expectedHash: hash,
          version: 'auto-discovered',
          lastVerified: new Date()
        };
        this.manifests.set(scanner, manifest);
        discovered.push(manifest);
      }
    }
    return discovered;
  }

  /**
   * Monitor scanner process behavior during execution
   * @param scannerName - Name of the scanner being monitored
   * @param pid - Process ID to monitor
   * @returns Array of alerts generated during monitoring
   */
  async monitorExecution(scannerName: string, pid: number): Promise<SupplyChainAlert[]> {
    const alerts: SupplyChainAlert[] = [];
    const netPath = `/proc/${pid}/net/tcp`;
    const fdPath = `/proc/${pid}/fd`;
    
    try {
      const netData = await readFile(netPath, 'utf8');
      const lines = netData.split('\n').slice(1);
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length > 2) {
          const remoteAddr = parts[2];
          if (remoteAddr && remoteAddr !== '00000000:0000') {
            const [ipHex, portHex] = remoteAddr.split(':');
            if (ipHex && !this.isLocalhost(ipHex)) {
              const alert: SupplyChainAlert = {
                type: 'unexpected_network',
                severity: 'high',
                scanner: scannerName,
                details: `Unexpected outbound connection to ${this.parseHexIp(ipHex)}:${parseInt(portHex ?? '0', 16)}`,
                timestamp: new Date()
              };
              alerts.push(alert);
              this.emitAlert(alert);
            }
          }
        }
      }
      
      const fds = await readdir(fdPath);
      for (const fd of fds) {
        try {
          const link = await readlink(join(fdPath, fd));
          if (link.includes('/tmp/') || link.includes('/var/tmp/') || link.includes('socket:')) {
            const alert: SupplyChainAlert = {
              type: 'unexpected_file_write',
              severity: 'medium',
              scanner: scannerName,
              details: `Suspicious file descriptor: ${link}`,
              timestamp: new Date()
            };
            alerts.push(alert);
            this.emitAlert(alert);
          }
        } catch {}
      }
    } catch (err) {
      const alert: SupplyChainAlert = {
        type: 'unexpected_file_write',
        severity: 'medium',
        scanner: scannerName,
        details: `Failed to monitor process: ${err}`,
        timestamp: new Date()
      };
      alerts.push(alert);
      this.emitAlert(alert);
    }
    
    return alerts;
  }

  /**
   * Validate package integrity against registry
   * @param packageName - Package name to validate
   * @param registry - Package registry type
   * @returns Validation result
   */
  async validatePackage(packageName: string, registry: 'npm' | 'pip'): Promise<{ valid: boolean; reason?: string }> {
    if (registry === 'npm') {
      try {
        const npmInfo = await new Promise<string>((resolve, reject) => {
          const proc = spawn('npm', ['view', packageName, 'dist.integrity', '--json'], { stdio: ['ignore', 'pipe', 'ignore'] });
          let data = '';
          proc.stdout.on('data', d => data += d);
          proc.on('close', c => c === 0 ? resolve(data) : reject(new Error('npm view failed')));
        });
        const integrity = JSON.parse(npmInfo);
        if (!integrity) {
          const alert: SupplyChainAlert = {
            type: 'unsigned_package',
            severity: 'high',
            scanner: 'npm',
            details: `Package ${packageName} lacks integrity hash`,
            timestamp: new Date()
          };
          this.emitAlert(alert);
          return { valid: false, reason: 'Missing integrity hash' };
        }
        return { valid: true };
      } catch (e) {
        return { valid: false, reason: String(e) };
      }
    } else {
      try {
        const pypiInfo = await new Promise<string>((resolve, reject) => {
          const proc = spawn('pip', ['index', 'versions', packageName], { stdio: ['ignore', 'pipe', 'ignore'] });
          let data = '';
          proc.stdout.on('data', d => data += d);
          proc.on('close', c => c === 0 ? resolve(data) : reject(new Error('pip index failed')));
        });
        const versionMatch = pypiInfo.match(/Available versions: (.+)/);
        const latestVersion = versionMatch ? (versionMatch[1] ?? '').split(',')[0]?.trim() ?? null : null;
        
        if (!latestVersion) {
          return { valid: false, reason: 'Could not determine PyPI version' };
        }
        
        const githubCheck = await new Promise<boolean>((resolve) => {
          const proc = spawn('curl', ['-s', '-o', '/dev/null', '-w', '%{http_code}', `https://github.com/${packageName}/releases/tag/v${latestVersion}`], { stdio: ['ignore', 'pipe', 'ignore'] });
          let code = '';
          proc.stdout.on('data', d => code += d);
          proc.on('close', () => resolve(code.trim() === '200'));
        });
        
        if (!githubCheck) {
          const alert: SupplyChainAlert = {
            type: 'version_mismatch',
            severity: 'critical',
            scanner: 'pip',
            details: `LiteLLM-style attack detected: ${packageName}@${latestVersion} on PyPI without matching GitHub release`,
            timestamp: new Date()
          };
          this.emitAlert(alert);
          return { valid: false, reason: 'PyPI release without GitHub tag (possible compromise)' };
        }
        
        return { valid: true };
      } catch (e) {
        return { valid: false, reason: String(e) };
      }
    }
  }

  /**
   * Get all alerts generated by the guard
   * @returns Array of supply chain alerts
   */
  getAlerts(): SupplyChainAlert[] {
    return [...this.alerts];
  }

  /**
   * Clear all alerts after review
   */
  clearAlerts(): void {
    this.alerts = [];
  }
}

/**
 * Factory function to create a new SupplyChainGuard instance
 * @returns New SupplyChainGuard instance
 */
export function createSupplyChainGuard(): SupplyChainGuard {
  return new SupplyChainGuard();
}
