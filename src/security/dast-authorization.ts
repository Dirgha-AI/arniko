import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { resolve } from 'path';
import { homedir } from 'os';
import { resolveTxt } from 'dns/promises';

export class DASTAuthorization {
  private configPath = resolve(homedir(), '.arniko/authorized-targets.json');
  private load(): string[] { try { return JSON.parse(readFileSync(this.configPath, 'utf8')); } catch { return []; } }
  private save(t: string[]): void { mkdirSync(resolve(this.configPath, '..'), { recursive: true }); writeFileSync(this.configPath, JSON.stringify(t)); }
  async authorize(target: string): Promise<{authorized: boolean, scope: string[]}> {
    const authorized = this.load().includes(target);
    return { authorized, scope: authorized ? ['dast'] : [] };
  }
  async verifyOwnership(domain: string, token: string): Promise<boolean> {
    try {
      const txt = await resolveTxt(domain).then(r => r.flat());
      if (txt.some(r => r.includes(`arniko-verify=${token}`))) return true;
      const html = await fetch(`https://${domain}`).then(r => r.text());
      return html.includes(`arniko-verify=${token}`);
    } catch { return false; }
  }
  getAuthorizedTargets(): string[] { return this.load(); }
  async addTarget(domain: string, token: string): Promise<void> {
    if (!await this.verifyOwnership(domain, token)) throw new Error('Verification failed');
    const list = this.load();
    if (!list.includes(domain)) { list.push(domain); this.save(list); }
  }
  revokeTarget(domain: string): void { this.save(this.load().filter(d => d !== domain)); }
}
