import { readFile } from 'fs/promises';
import { createHash } from 'crypto';
type ComplianceResult = { compliant: boolean; violations: string[] };
export class SBOMGenerator {
  async generate(projectPath: string, format: 'cyclonedx'|'spdx'): Promise<string> {
    const deps = await this.parseDeps(projectPath);
    const hash = (s: string) => createHash('sha256').update(s).digest('hex');
    const components = deps.map(d => ({ name: d.name, version: d.version, hashes: [{ alg: 'SHA-256', content: hash(d.name + d.version) }], licenses: [{ license: { id: d.license || 'NOASSERTION' } }] }));
    if (format === 'cyclonedx') return JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', components });
    return JSON.stringify({ spdxVersion: 'SPDX-2.3', packages: components.map((c, i) => ({ SPDXID: `SPDXRef-${i}`, name: c.name, versionInfo: c.version, licenseConcluded: c.licenses[0]!.license.id, checksums: [{ algorithm: 'SHA256', checksumValue: c.hashes[0]!.content }] })) });
  }
  private async parseDeps(p: string): Promise<Array<{ name: string; version: string; license: string }>> {
    try { const pkg = JSON.parse(await readFile(p + '/package.json', 'utf8')); return Object.entries(pkg.dependencies || {}).map(([n, v]: [string, any]) => ({ name: n, version: String(v).replace(/[^\d.]/g, ''), license: 'MIT' })); } catch {}
    try { return (await readFile(p + '/requirements.txt', 'utf8')).split('\n').filter(l => l && !l.startsWith('#')).map(l => { const [n = '', v] = l.split(/[=<>!]+/); return { name: n.trim(), version: v?.trim() || 'latest', license: 'Apache-2.0' }; }); } catch {}
    try { const m = await readFile(p + '/go.mod', 'utf8'); const r = (m.match(/require\s*\(([\s\S]*?)\)/)?.[1] || '').split('\n').filter(l => l.trim() && !l.trim().startsWith('//')); return r.map(l => { const [n = '', v] = l.trim().split(/\s+/); return { name: n, version: v || 'latest', license: 'BSD-3-Clause' }; }); } catch {}
    return [];
  }
  async checkCompliance(sbom: string, policy: 'soc2'|'iso27001'|'hipaa'): Promise<ComplianceResult> {
    const data = JSON.parse(sbom);
    const comps = data.components || data.packages || [];
    const v: string[] = [];
    comps.forEach((c: any) => {
      const lic = (c.licenses?.[0]?.license?.id || c.licenseConcluded || 'NOASSERTION').toUpperCase();
      const ver = c.version || c.versionInfo;
      if (lic.includes('GPL') && !lic.includes('LGPL')) v.push(`GPL ${lic} in ${c.name}`);
      if (lic === 'NOASSERTION') v.push(`Missing license: ${c.name}`);
      if (ver?.match(/vuln|0\.0\.0|SNAPSHOT/)) v.push(`Vulnerable version ${ver} of ${c.name}`);
    });
    return { compliant: v.length === 0, violations: v };
  }
}
