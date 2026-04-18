import { spawn } from 'child_process';
interface Finding { severity: string; type: 'iac'; check_id: string; resource: string; file: string; guideline: string; }
export class CheckovScanner {
async isInstalled(): Promise<boolean> { return new Promise(r => { const p = spawn('checkov', ['--version']); p.on('error', () => r(false)); p.on('close', c => r(c === 0)); }); }
async scan(path: string, framework?: 'terraform'|'cloudformation'|'kubernetes'): Promise<Finding[]> {
const args = ['-d', path, '--output', 'json']; if (framework) args.push('--framework', framework);
const proc = spawn('checkov', args, { stdio: ['ignore', 'pipe', 'inherit'] });
let out = ''; proc.stdout.on('data', d => out += d);
return new Promise((res, rej) => {
proc.on('error', rej);
proc.on('close', () => {
try {
const data = JSON.parse(out);
const checks = data.results?.failed_checks || [];
res(checks.map((c: any) => ({ severity: c.severity || 'MEDIUM', type: 'iac', check_id: c.check_id, resource: c.resource, file: c.file_path, guideline: c.guideline || '' })));
} catch (e) { rej(e); }
});
});
}
}
