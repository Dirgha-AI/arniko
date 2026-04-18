import { execFile } from 'child_process';
import { promisify } from 'util';
const exec = promisify(execFile);

export interface Finding { severity: string; type: 'sca' | 'iac'; package: string; version: string; fixed_version: string; cve: string; description: string }

export class TrivyScanner {
  private async run(args: string[]): Promise<any> { try { const { stdout } = await exec('trivy', args, { timeout: 60000 }); return JSON.parse(stdout); } catch { return null; } }
  private parse(r: any, t: 'sca' | 'iac'): Finding[] { return r?.Results?.flatMap((x: any) => (x.Vulnerabilities || x.Misconfigurations || []).map((v: any) => ({ severity: v.Severity, type: t, package: v.PkgName || v.ID, version: v.InstalledVersion || '', fixed_version: v.FixedVersion || '', cve: v.VulnerabilityID || v.ID, description: v.Title || v.Description }))) || []; }
  async isInstalled(): Promise<boolean> { try { await exec('trivy', ['--version'], { timeout: 5000 }); return true; } catch { return false; } }
  async scanFilesystem(path: string): Promise<Finding[]> { return this.parse(await this.run(['filesystem', '--format', 'json', path]), 'sca'); }
  async scanImage(image: string): Promise<Finding[]> { return this.parse(await this.run(['image', '--format', 'json', image]), 'sca'); }
  async scanConfig(path: string): Promise<Finding[]> { return this.parse(await this.run(['config', '--format', 'json', path]), 'iac'); }
}
