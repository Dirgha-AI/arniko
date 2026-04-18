// @ts-ignore - optional peer dependency
import { load } from 'js-yaml';
// @ts-ignore - optional peer dependency
import { neon } from '@neondatabase/serverless';

export class ToolAttestation {
  private policy: { blocked: string[]; approval: string[]; auto: string[] };
  private sql: ReturnType<typeof neon>;

  constructor(yamlConfig: string, dbUrl: string) {
    this.policy = load(yamlConfig) as any;
    this.sql = neon(dbUrl);
  }

  async attest(tool: { name: string; args: Record<string, unknown>; requestedBy: string }): Promise<{ allowed: boolean; reason?: string }> {
    const n = tool.name.toLowerCase(), a = JSON.stringify(tool.args).toLowerCase();
    if (this.policy.blocked.some(b => n.includes(b) || a.includes(b))) return { allowed: false, reason: 'Blocked' };
    if (this.policy.approval.includes(n)) return { allowed: false, reason: 'Requires approval' };
    return { allowed: true };
  }

  async logAttestation(tool: string, allowed: boolean, requestedBy: string): Promise<void> {
    await this.sql`INSERT INTO attestations (tool, allowed, requested_by, ts) VALUES (${tool}, ${allowed}, ${requestedBy}, NOW())`;
  }
}
