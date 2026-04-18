interface Finding { severity: 'critical'|'high'|'medium'|'low'; message: string; }

export class BuckyMeshIntegration {
  constructor(private baseUrl: string = 'http://localhost:8080') {}
  
  async registerHook(): Promise<void> {
    await fetch(`${this.baseUrl}/api/bucky/hooks/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'arniko-scan', event: 'task.before_execute', endpoint: '/api/arniko/scan' })
    });
  }
  
  async onTaskSubmitted(task: { code: string; language: string }): Promise<{ safe: boolean; findings: Finding[] }> {
    const findings: Finding[] = [];
    if (/password|secret|key/i.test(task.code)) findings.push({ severity: 'high', message: 'Secret pattern detected' });
    if (/eval\(|exec\(/.test(task.code)) findings.push({ severity: 'critical', message: 'Code injection risk' });
    return { safe: !findings.some(f => f.severity === 'critical' || f.severity === 'high'), findings };
  }
  
  async scanMeshNode(nodeId: string): Promise<Finding[]> {
    const cfg = await (await fetch(`${this.baseUrl}/api/bucky/nodes/${nodeId}/config`)).json();
    const findings: Finding[] = [];
    if (!cfg.tls) findings.push({ severity: 'high', message: 'TLS disabled' });
    if (cfg.openPorts?.includes(22)) findings.push({ severity: 'medium', message: 'SSH exposed' });
    return findings;
  }
}
