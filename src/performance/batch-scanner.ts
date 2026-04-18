import { exec } from "child_process"; import { promisify } from "util"; import { rm } from "fs/promises";
type Severity = "critical" | "high" | "medium" | "low"; interface Finding { severity: Severity; }
interface BatchResult { repo: string; findings: Finding[]; error?: string; }
const execAsync = promisify(exec);

export class BatchScanner {
  onProgress?: (c: number, t: number, r: string) => void;
  async scanBatch(repos: string[], concurrency = 10): Promise<BatchResult[]> {
    const results: BatchResult[] = [], q = [...repos], total = repos.length;
    let completed = 0;
    const scan = async (repo: string): Promise<BatchResult> => {
      this.onProgress?.(completed, total, repo);
      const dir = `/tmp/arniko-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      try {
        await execAsync(`git clone --depth 1 ${repo} ${dir}`, { timeout: 60000 });
        const findings: Finding[] = []; // run scanners here
        await rm(dir, { recursive: true, force: true });
        this.onProgress?.(++completed, total, repo);
        return { repo, findings };
      } catch (e) {
        this.onProgress?.(++completed, total, repo);
        return { repo, findings: [], error: (e as Error).message };
      }
    };
    const workers = Array(concurrency).fill(0).map(async () => { while (q.length) results.push(await scan(q.shift()!)); });
    await Promise.all(workers);
    return results;
  }
  aggregate(results: BatchResult[]): Record<Severity, number> {
    const a = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const r of results) for (const f of r.findings) a[f.severity]++;
    return a;
  }
}
