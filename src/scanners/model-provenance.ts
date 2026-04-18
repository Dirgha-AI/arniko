import { createHash } from "crypto"; import { readFileSync, readdirSync } from "fs"; import { join } from "path";
type Trust = "verified" | "community" | "unknown"; export interface ProvenanceFinding { check: string; passed: boolean; trust: Trust; details?: string; }
export class ModelProvenanceScanner {
  private known = new Set<string>(); private reg = ["huggingface.co", "ollama.com"]; private lic = ["apache", "mit", "cc-by"];
  async verifyModel(p: string): Promise<ProvenanceFinding[]> {
    const f = readdirSync(p), r: ProvenanceFinding[] = [], b = f.find(x => x.endsWith(".bin")) || "", h = b ? createHash("sha256").update(readFileSync(join(p, b))).digest("hex") : "";
    r.push({ check: "hash", passed: this.known.has(h), trust: this.known.has(h) ? "verified" : "unknown", details: h.slice(0, 8) });
    const c = f.find(x => /readme|model_card/i.test(x)), t = c ? readFileSync(join(p, c), "utf8").toLowerCase() : "";
    r.push({ check: "card", passed: !!c, trust: c ? "community" : "unknown" });
    r.push({ check: "license", passed: this.lic.some(x => t.includes(x)), trust: t.includes("apache-2") ? "verified" : "community" });
    r.push({ check: "signed", passed: f.some(x => x.endsWith(".safetensors")) && !f.some(x => x.endsWith(".bin")), trust: "verified" });
    r.push({ check: "registry", passed: this.reg.some(x => t.includes(x)), trust: "community" });
    return r;
  }
  async scanHuggingFaceModel(i: string): Promise<ProvenanceFinding[]> {
    const d = await (await fetch(`https://huggingface.co/api/models/${i}`)).json(), r: ProvenanceFinding[] = [];
    r.push({ check: "publisher", passed: ["meta", "google", "microsoft"].includes(d.author), trust: ["meta", "google"].includes(d.author) ? "verified" : "community", details: d.author });
    r.push({ check: "popularity", passed: d.downloads > 1e4, trust: d.downloads > 1e5 ? "verified" : "community", details: d.downloads });
    r.push({ check: "card", passed: !!d.cardData, trust: d.cardData ? "community" : "unknown" });
    return r;
  }
}
