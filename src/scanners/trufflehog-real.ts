import { spawn } from 'child_process'; import { promisify } from 'util'; import { exec } from 'child_process'; const execAsync = promisify(exec);
interface SecretFinding { type: 'secret'; detector_name: string; file: string; line: number; raw_v2: string; verified: boolean; }
export class TruffleHogScanner {
  private redact(s: string): string { return s?.length > 8 ? s.slice(0,4)+'****'+s.slice(-4) : '****'; }
  async isInstalled(): Promise<boolean> { try { await execAsync('trufflehog --version'); return true; } catch { return false; } }
  private async runScan(args: string[]): Promise<SecretFinding[]> {
    return new Promise((res, rej) => {
      const f: SecretFinding[] = [], p = spawn('trufflehog', args, {stdio: ['ignore','pipe','pipe']});
      p.stdout.on('data', d => d.toString().split('\n').forEach((l: string) => { if(!l.trim())return; try{const j=JSON.parse(l),m=j.SourceMetadata?.Data; const file=m?.Filesystem?.file||m?.Git?.file||''; if(file)f.push({type:'secret',detector_name:j.DetectorName||'',file,line:m?.Filesystem?.line||m?.Git?.line||0,raw_v2:this.redact(j.Raw||j.RawV2||''),verified:j.Verified||false});}catch{}}));
      p.on('close', c => c===0||f.length?res(f):rej(new Error('Exit '+c)));
      p.on('error', rej);
    });
  }
  async scanRepo(repoPath: string): Promise<SecretFinding[]> { return this.runScan(['filesystem','--json',repoPath]); }
  async scanGitHistory(repoPath: string): Promise<SecretFinding[]> { return this.runScan(['git','file://'+repoPath,'--json']); }
}
