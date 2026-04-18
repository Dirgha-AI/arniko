import { readFile, writeFile } from "fs/promises";

interface SecurityFinding {
  type: "hardcoded_secret" | "sql_injection" | "eval_usage" | "missing_auth";
  filePath: string;
  line: number;
  match: string;
  varName?: string;
}

export class FixAgent {
  async fix(f: SecurityFinding): Promise<{fixed: boolean; diff: string}> {
    const o = (await readFile(f.filePath, "utf8")).split("\n");
    const n = [...o], i = f.line - 1;
    if (f.type === "hardcoded_secret") n[i] = (n[i] ?? '').replace(f.match, `process.env.${f.varName || "SECRET"}`);
    else if (f.type === "sql_injection") n[i] = (n[i] ?? '').replace(f.match, "/* parameterized query */");
    else if (f.type === "eval_usage") n[i] = (n[i] ?? '').replace(/eval\((.*)\)/, "JSON.parse($1)");
    else if (f.type === "missing_auth") { n.unshift("import { authMiddleware } from './auth';"); n[i+1] = `authMiddleware(${n[i+1] ?? ''})`; }
    return {fixed: true, diff: this.diff(o, n, f.filePath)};
  }
  
  diff(o: string[], n: string[], p: string): string {
    let d = `--- a/${p}\n+++ b/${p}\n`, i = 0;
    while (i < Math.max(o.length, n.length)) {
      if (o[i] !== n[i]) {
        let j = i;
        while (j < Math.max(o.length, n.length) && o[j] !== n[j]) j++;
        d += `@@ -${i+1},${j-i} +${i+1},${j-i} @@\n`;
        for (let k = i; k < j; k++) { if (o[k]) d += `-${o[k]}\n`; if (n[k]) d += `+${n[k]}\n`; }
        i = j;
      } else i++;
    }
    return d;
  }
  
  async applyFix(p: string, d: string): Promise<void> {
    let c = (await readFile(p, "utf8")).split("\n");
    const h = [...d.matchAll(/@@ -(\d+),(\d+) \+(\d+),(\d+) @@/g)].reverse();
    for (const m of h) {
      const s = parseInt(m[1] ?? '1') - 1, len = parseInt(m[2] ?? '0');
      const add = d.slice(m.index! + m[0].length).split("\n").filter(l => l.startsWith("+") && !l.startsWith("+++")).map(l => l.slice(1));
      c.splice(s, len, ...add);
    }
    await writeFile(p, c.join("\n"));
  }
}
