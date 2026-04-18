import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

interface Finding {
  severity: string;
  type: 'sast';
  rule_id: string;
  message: string;
  file: string;
  line: number;
  code_snippet: string;
}

export class SemgrepScanner {
  async isInstalled(): Promise<boolean> {
    try {
      await execFileAsync('semgrep', ['--version'], { timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }

  async scan(targetPath: string, rules?: string[]): Promise<Finding[]> {
    if (!(await this.isInstalled())) throw new Error('Semgrep not installed. Please install semgrep.');
    const args = ['scan', '--json', '--max-target-bytes', '1000000', ...(rules ? rules.flatMap(r => ['--config', r]) : ['--config=auto']), targetPath];
    const { stdout } = await execFileAsync('semgrep', args, { timeout: 30000 });
    const data = JSON.parse(stdout);
    return data.results.map((r: any) => ({
      severity: r.extra?.severity || 'UNKNOWN',
      type: 'sast',
      rule_id: r.check_id,
      message: r.extra?.message || '',
      file: r.path,
      line: r.start?.line || 0,
      code_snippet: r.extra?.lines || ''
    }));
  }

  async getAvailableRules(): Promise<string[]> {
    if (!(await this.isInstalled())) throw new Error('Semgrep not installed. Please install semgrep.');
    const { stdout } = await execFileAsync('semgrep', ['registry', 'list', '--json'], { timeout: 30000 });
    return JSON.parse(stdout).map((r: any) => r.id || r.name);
  }
}
