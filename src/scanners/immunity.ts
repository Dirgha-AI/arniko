import { readdir, readFile, stat } from "fs/promises";
import { join } from "path";

interface SecurityFinding { severity: "critical" | "high" | "medium" | "low"; type: string; file: string; line: number; description: string; fix: string; }

abstract class BaseScanner { abstract scan(target: string): Promise<SecurityFinding[]>; }

export class ImmunityScanner extends BaseScanner {
  async scan(target: string): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const checks = [
      { r: /(api[_-]?key|token|password)\s*[=:]\s*["'][\w-]{16,}["']/gi, t: "Hardcoded Secret", s: "critical", d: "Credential exposed", f: "Use env vars" },
      { r: /eval\s*\(|new\s+Function\s*\(|exec\s*\(/g, t: "Unsafe Execution", s: "critical", d: "Code injection risk", f: "Avoid dynamic execution" },
      { r: /(SELECT|INSERT|UPDATE|DELETE).*\+\s*[\w"']+/gi, t: "SQL Injection", s: "high", d: "Concatenated SQL", f: "Use parameterized queries" },
      { r: /innerHTML\s*=|dangerouslySetInnerHTML\s*=\s*\{\s*[^}]*\}/g, t: "XSS", s: "high", d: "Unsanitized HTML", f: "Use DOMPurify or textContent" },
      { r: /http:\/\/(?!localhost|127\.0\.0\.1)/g, t: "Insecure HTTP", s: "medium", d: "Non-TLS connection", f: "Use https://" },
      { r: /(app\.(get|post|put|delete)|router\.(get|post))\s*\([^)]*\)\s*(?!.*auth)/g, t: "Missing Auth", s: "high", d: "No auth middleware", f: "Add authentication" }
    ];
    const walk = async (dir: string) => {
      for (const f of await readdir(dir)) {
        const p = join(dir, f);
        if (f === "node_modules") continue;
        if ((await stat(p)).isDirectory()) await walk(p);
        else if (/\.(ts|tsx|js)$/.test(f)) {
          const content = await readFile(p, "utf8");
          content.split("\n").forEach((line, i) => {
            checks.forEach(c => {
              if (c.r.test(line)) findings.push({ severity: c.s as any, type: c.t, file: p, line: i + 1, description: c.d, fix: c.f });
              c.r.lastIndex = 0;
            });
          });
        }
      }
    };
    await walk(target);
    return findings;
  }
}
