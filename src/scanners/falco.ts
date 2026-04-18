import type { ScanTarget, ScanResult, ScanFinding, ScanSeverity } from '../types/index.js';

export type FalcoPriority = 'Emergency' | 'Alert' | 'Critical' | 'Error' | 'Warning' | 'Notice' | 'Info' | 'Debug';

export interface FalcoAlert {
  time: Date;
  rule: string;
  priority: FalcoPriority;
  output: string;
  outputFields: Record<string, string>;
}

interface FalcoConfig {
  endpoint?: string;
  rules?: string[];
}

interface FalcoEventResponse {
  output: string;
  priority: string;
  rule: string;
  time: string;
  output_fields?: Record<string, string>;
}

export class FalcoScanner {
  private readonly endpoint: string;
  private readonly rules: string[];

  constructor(config: FalcoConfig = {}) {
    this.endpoint = config.endpoint?.replace(/\/$/, '') || 'http://localhost:8765';
    this.rules = config.rules || [];
  }

  /**
   * Fetch Falco alerts from the events endpoint
   */
  async getAlerts(since?: Date, limit?: number): Promise<FalcoAlert[]> {
    const url = new URL('/events', this.endpoint);
    
    if (since) {
      url.searchParams.append('since', since.toISOString());
    }
    if (limit !== undefined && limit > 0) {
      url.searchParams.append('limit', limit.toString());
    }

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`Falco API error: ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as FalcoEventResponse[];
    
    return data.map(item => this.transformToAlert(item));
  }

  /**
   * Check if a specific rule exists and is loaded
   */
  async checkRule(ruleName: string): Promise<Record<string, unknown> | null> {
    const url = new URL(`/rules/${encodeURIComponent(ruleName)}`, this.endpoint);
    
    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      throw new Error(`Failed to check rule: ${response.status} ${response.statusText}`);
    }

    return response.json() as Promise<Record<string, unknown>>;
  }

  /**
   * Run a scan against a target, collecting recent alerts and mapping to findings
   */
  async run(target: ScanTarget): Promise<ScanResult> {
    // Default to last 5 minutes if no start time provided
    const since = (target as any).startTime || new Date(Date.now() - 5 * 60 * 1000);
    const alerts = await this.getAlerts(since, 1000);

    const findings = alerts.map(alert => ({
      id: `falco-${alert.rule}-${alert.time.getTime()}`,
      title: alert.rule,
      description: alert.output,
      severity: this.mapPriorityToSeverity(alert.priority),
      timestamp: alert.time,
      source: 'falco',
      metadata: {
        ...alert.outputFields,
        priority: alert.priority,
      },
    }));

    return {
      scanner: 'falco',
      target: target.identifier,
      scanTime: new Date(),
      findings,
      summary: {
        total: findings.length,
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
        info: findings.filter(f => f.severity === 'info').length,
      },
    } as unknown as ScanResult;
  }

  /**
   * Stream real-time alerts via WebSocket to /ws
   * Returns a cleanup function to close the connection
   * Note: Requires WebSocket to be available in the global scope (Node 18+, Deno, or Browser)
   */
  async streamAlerts(callback: (alert: FalcoAlert) => void): Promise<() => void> {
    const wsUrl = this.endpoint.replace(/^http/, 'ws') + '/ws';
    
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
        // Return cleanup function once connected
        resolve(() => {
          if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
            ws.close();
          }
        });
      };
      
      ws.onmessage = (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data) as FalcoEventResponse;
          const alert = this.transformToAlert(data);
          callback(alert);
        } catch (error) {
          console.error('Failed to parse Falco alert:', error);
        }
      };
      
      ws.onerror = (error: Event) => {
        console.error('Falco WebSocket error:', error);
        reject(new Error('WebSocket connection failed'));
      };
      
      ws.onclose = () => {
        // Connection closed
      };
    });
  }

  /**
   * Generate mock alerts for testing without a live Falco instance
   * Includes: unexpected process, write to /etc, outbound connection
   */
  simulateScan(): FalcoAlert[] {
    const now = new Date();
    const containerId = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';
    
    return [
      {
        time: new Date(now.getTime() - 2000),
        rule: 'Unexpected process spawned',
        priority: 'Warning',
        output: `${now.toISOString()}: Warning Unexpected process spawned (user=root command=nc -lvp 4444)`,
        outputFields: {
          user: 'root',
          command: 'nc -lvp 4444',
          pid: '12345',
          container_id: containerId,
          proc_name: 'nc',
        },
      },
      {
        time: new Date(now.getTime() - 8000),
        rule: 'Write to /etc',
        priority: 'Critical',
        output: `${now.toISOString()}: Critical Sensitive file opened for writing (user=root file=/etc/shadow)`,
        outputFields: {
          user: 'root',
          file: '/etc/shadow',
          proc_name: 'vi',
          container_id: containerId,
          fd_name: '/etc/shadow',
        },
      },
      {
        time: new Date(now.getTime() - 15000),
        rule: 'Outbound connection',
        priority: 'Notice',
        output: `${now.toISOString()}: Notice Outbound connection from container (user=www-data dest=192.168.1.100:4444)`,
        outputFields: {
          user: 'www-data',
          dest: '192.168.1.100:4444',
          proc_name: 'curl',
          container_id: containerId,
          fd_name: '192.168.1.100:4444',
        },
      },
    ];
  }

  private transformToAlert(item: FalcoEventResponse): FalcoAlert {
    return {
      time: new Date(item.time),
      rule: item.rule,
      priority: item.priority as FalcoPriority,
      output: item.output,
      outputFields: item.output_fields || {},
    };
  }

  private mapPriorityToSeverity(priority: FalcoPriority): string {
    const mapping: Record<FalcoPriority, string> = {
      'Emergency': 'critical',
      'Alert': 'critical',
      'Critical': 'high',
      'Error': 'high',
      'Warning': 'medium',
      'Notice': 'low',
      'Info': 'info',
      'Debug': 'info',
    };
    return mapping[priority] || 'unknown';
  }
}