interface AuditEvent {
  id: string;
  timestamp: string;
  eventType: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  userId: string;
  action: string;
  resource: string;
  outcome: 'success' | 'blocked' | 'error';
  details: Record<string, unknown>;
  sourceIp?: string;
  userAgent?: string;
  previousHash: string;
  currentHash: string;
}

interface ScanResult {
  ruleId: string;
  message: string;
  level: 'error' | 'warning' | 'note' | 'none';
  locations: Array<{
    physicalLocation: {
      artifactLocation: {
        uri: string;
      };
      region: {
        startLine: number;
        startColumn?: number;
        endLine?: number;
        endColumn?: number;
      };
    };
  }>;
  properties?: Record<string, unknown>;
}

interface AuditLoggerConfig {
  storage: 'postgres' | 'file';
  retentionDays: number;
  exportFormat: 'csv' | 'json' | 'sarif';
  filePath?: string;
}

interface SIEMConnectorConfig {
  type: 'splunk' | 'datadog' | 'elastic' | 'sentinel';
  endpoint: string;
  apiKey: string;
  workspaceId?: string;
}

interface HealthCheckResult {
  connected: boolean;
  latencyMs: number;
}

interface ChainIntegrityResult {
  valid: boolean;
  brokenAt?: number;
}

function bufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

/**
 * AuditLogger provides tamper-evident audit logging with hash chain integrity,
 * multiple export formats, and retention management for SOC2 compliance.
 */
export class AuditLogger {
  private config: AuditLoggerConfig;
  private events: AuditEvent[] = [];
  private lastHash: string = '0'.repeat(64);

  /**
   * Creates an instance of AuditLogger.
   * @param config - Configuration for storage, retention, and export settings
   */
  constructor(config: AuditLoggerConfig) {
    this.config = config;
  }

  /**
   * Computes SHA-256 hash of the provided data.
   * @param data - String data to hash
   * @returns Hexadecimal representation of the hash
   */
  private async computeHash(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    return bufferToHex(hashBuffer);
  }

  /**
   * Logs a new audit event with automatic ID generation, timestamping, and hash chaining.
   * @param event - Partial audit event data (id, timestamp, and hashes will be auto-generated)
   * @returns The complete audit event with generated fields
   */
  async logEvent(event: Partial<AuditEvent>): Promise<AuditEvent> {
    const id = generateUUID();
    const timestamp = new Date().toISOString();
    
    const eventWithoutCurrentHash = {
      id,
      timestamp,
      eventType: event.eventType || 'unknown',
      severity: event.severity || 'info',
      userId: event.userId || 'system',
      action: event.action || 'unknown',
      resource: event.resource || 'unknown',
      outcome: event.outcome || 'success',
      details: event.details || {},
      sourceIp: event.sourceIp,
      userAgent: event.userAgent,
      previousHash: this.lastHash
    };
    
    const currentHash = await this.computeHash(JSON.stringify(eventWithoutCurrentHash));
    
    const completeEvent: AuditEvent = {
      ...eventWithoutCurrentHash,
      currentHash
    } as AuditEvent;

    this.events.push(completeEvent);
    this.lastHash = currentHash;
    
    return completeEvent;
  }

  /**
   * Exports events within the specified date range as CSV format.
   * @param start - Start date for filtering
   * @param end - End date for filtering
   * @returns CSV string with headers and filtered event data
   */
  async exportCSV(start: Date, end: Date): Promise<string> {
    const filtered = this.events.filter(e => {
      const ts = new Date(e.timestamp);
      return ts >= start && ts <= end;
    });

    const headers = [
      'id', 'timestamp', 'eventType', 'severity', 'userId', 
      'action', 'resource', 'outcome', 'sourceIp', 'userAgent',
      'previousHash', 'currentHash', 'details'
    ];

    const rows = filtered.map(e => [
      e.id,
      e.timestamp,
      e.eventType,
      e.severity,
      e.userId,
      e.action,
      e.resource,
      e.outcome,
      e.sourceIp || '',
      e.userAgent || '',
      e.previousHash,
      e.currentHash,
      JSON.stringify(e.details)
    ].map(field => `"${String(field).replace(/"/g, '""')}"`).join(','));

    return [headers.join(','), ...rows].join('\n');
  }

  /**
   * Exports events within the specified date range as JSON format.
   * @param start - Start date for filtering
   * @param end - End date for filtering
   * @returns JSON string of filtered events
   */
  async exportJSON(start: Date, end: Date): Promise<string> {
    const filtered = this.events.filter(e => {
      const ts = new Date(e.timestamp);
      return ts >= start && ts <= end;
    });
    return JSON.stringify(filtered, null, 2);
  }

  /**
   * Exports scan results as SARIF v2.1.0 format compatible with GitHub Code Scanning.
   * @param results - Array of scan results to convert
   * @returns SARIF v2.1.0 JSON string
   */
  async exportSARIF(results: ScanResult[]): Promise<string> {
    const sarif = {
      version: '2.1.0',
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs: [{
        tool: {
          driver: {
            name: 'arniko-security',
            informationUri: 'https://arniko.io/security',
            rules: results.map(r => ({
              id: r.ruleId,
              shortDescription: {
                text: r.message.substring(0, 100)
              },
              fullDescription: {
                text: r.message
              },
              defaultConfiguration: {
                level: r.level === 'error' ? 'error' : r.level === 'warning' ? 'warning' : 'note'
              }
            }))
          }
        },
        results: results.map(r => ({
          ruleId: r.ruleId,
          level: r.level,
          message: {
            text: r.message
          },
          locations: r.locations.map(loc => ({
            physicalLocation: {
              artifactLocation: {
                uri: loc.physicalLocation.artifactLocation.uri
              },
              region: {
                startLine: loc.physicalLocation.region.startLine,
                startColumn: loc.physicalLocation.region.startColumn,
                endLine: loc.physicalLocation.region.endLine,
                endColumn: loc.physicalLocation.region.endColumn
              }
            }
          })),
          properties: r.properties || {}
        }))
      }]
    };
    return JSON.stringify(sarif, null, 2);
  }

  /**
   * Removes events older than the configured retention period.
   */
  async purgeBeyondRetention(): Promise<void> {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - this.config.retentionDays);
    
    this.events = this.events.filter(e => {
      const ts = new Date(e.timestamp);
      return ts >= cutoff;
    });
  }

  /**
   * Verifies the integrity of the hash chain by recomputing hashes.
   * @returns Object indicating validity and optional index where chain was broken
   */
  async verifyChainIntegrity(): Promise<ChainIntegrityResult> {
    let previousHash = '0'.repeat(64);
    
    for (let i = 0; i < this.events.length; i++) {
      const event = this.events[i]!;

      if (event.previousHash !== previousHash) {
        return { valid: false, brokenAt: i };
      }

      const { currentHash, ...eventWithoutCurrentHash } = event;
      const computedHash = await this.computeHash(JSON.stringify(eventWithoutCurrentHash));

      if (computedHash !== currentHash) {
        return { valid: false, brokenAt: i };
      }
      
      previousHash = currentHash;
    }
    
    return { valid: true };
  }
}

/**
 * SIEMConnector provides integration with major SIEM platforms including
 * Splunk, Datadog, Elastic, and Azure Sentinel for real-time security event streaming.
 */
export class SIEMConnector {
  private config: SIEMConnectorConfig;

  /**
   * Creates an instance of SIEMConnector.
   * @param config - Configuration for SIEM type, endpoint, and authentication
   */
  constructor(config: SIEMConnectorConfig) {
    this.config = config;
  }

  /**
   * Pushes a single audit event to the configured SIEM platform.
   * @param event - The audit event to push
   * @throws Error if the push fails
   */
  async pushEvent(event: AuditEvent): Promise<void> {
    try {
      switch (this.config.type) {
        case 'splunk': {
          const payload = {
            event: event,
            sourcetype: 'arniko:security',
            index: 'security',
            time: new Date(event.timestamp).getTime() / 1000
          };
          
          const response = await fetch(`${this.config.endpoint}/services/collector/event`, {
            method: 'POST',
            headers: {
              'Authorization': `Splunk ${this.config.apiKey}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
          });
          
          if (!response.ok) {
            throw new Error(`Splunk HEC error: ${response.status} ${response.statusText}`);
          }
          break;
        }
        
        case 'datadog': {
          const payload = {
            ddsource: 'arniko',
            ddtags: 'service:arniko,env:production',
            hostname: 'arniko-security',
            message: JSON.stringify(event),
            service: 'arniko-security',
            status: event.severity === 'critical' || event.severity === 'high' ? 'error' : 
                    event.severity === 'medium' ? 'warning' : 'info',
            timestamp: new Date(event.timestamp).getTime()
          };
          
          const response = await fetch(`${this.config.endpoint}/api/v2/logs`, {
            method: 'POST',
            headers: {
              'DD-API-KEY': this.config.apiKey,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
          });
          
          if (!response.ok) {
            throw new Error(`Datadog API error: ${response.status} ${response.statusText}`);
          }
          break;
        }
        
        case 'elastic': {
          const payload = {
            index: {
              _index: 'arniko-events',
              _id: event.id
            }
          };
          const doc = {
            ...event,
            '@timestamp': event.timestamp
          };
          
          const bulkBody = [
            JSON.stringify(payload),
            JSON.stringify(doc)
          ].join('\n') + '\n';
          
          const response = await fetch(`${this.config.endpoint}/_bulk`, {
            method: 'POST',
            headers: {
              'Authorization': `ApiKey ${this.config.apiKey}`,
              'Content-Type': 'application/x-ndjson'
            },
            body: bulkBody
          });
          
          if (!response.ok) {
            throw new Error(`Elastic API error: ${response.status} ${response.statusText}`);
          }
          break;
        }
        
        case 'sentinel': {
          if (!this.config.workspaceId) {
            throw new Error('Workspace ID required for Azure Sentinel');
          }
          
          const payload = {
            EventType: event.eventType,
            EventTime: event.timestamp,
            Severity: event.severity,
            UserId: event.userId,
            Action: event.action,
            Resource: event.resource,
            Outcome: event.outcome,
            Details: event.details,
            SourceIp: event.sourceIp,
            UserAgent: event.userAgent
          };
          
          const bodyString = JSON.stringify(payload);
          const contentLength = bodyString.length;
          const rfc1123date = new Date().toUTCString();
          const stringToHash = ['POST', contentLength.toString(), 'application/json', rfc1123date, '/api/logs'].join('\n');
          
          const encoder = new TextEncoder();
          const keyData = encoder.encode(this.config.apiKey);
          const messageData = encoder.encode(stringToHash);
          
          const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
          );
          
          const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
          const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
          
          const response = await fetch(`${this.config.endpoint}/${this.config.workspaceId}/api/logs?api-version=2016-04-01`, {
            method: 'POST',
            headers: {
              'Authorization': `SharedKey ${this.config.workspaceId}:${signatureBase64}`,
              'Log-Type': 'ArnikoSecurity',
              'x-ms-date': rfc1123date,
              'Content-Type': 'application/json'
            },
            body: bodyString
          });
          
          if (!response.ok) {
            throw new Error(`Sentinel API error: ${response.status} ${response.statusText}`);
          }
          break;
        }
      }
    } catch (error) {
      throw new Error(`Failed to push event to ${this.config.type}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Pushes a batch of audit events to the configured SIEM platform.
   * @param events - Array of audit events to push
   * @throws Error if the batch push fails
   */
  async pushBatch(events: AuditEvent[]): Promise<void> {
    if (events.length === 0) return;
    
    const chunkSize = 100;
    for (let i = 0; i < events.length; i += chunkSize) {
      const chunk = events.slice(i, i + chunkSize);
      
      if (this.config.type === 'elastic') {
        const bulkBody = chunk.map(event => [
          JSON.stringify({ index: { _index: 'arniko-events', _id: event.id } }),
          JSON.stringify({ ...event, '@timestamp': event.timestamp })
        ].join('\n')).join('\n') + '\n';
        
        const response = await fetch(`${this.config.endpoint}/_bulk`, {
          method: 'POST',
          headers: {
            'Authorization': `ApiKey ${this.config.apiKey}`,
            'Content-Type': 'application/x-ndjson'
          },
          body: bulkBody
        });
        
        if (!response.ok) {
          throw new Error(`Elastic batch error: ${response.status} ${response.statusText}`);
        }
      } else {
        await Promise.all(chunk.map(e => this.pushEvent(e)));
      }
    }
  }

  /**
   * Performs a health check against the SIEM endpoint.
   * @returns Object containing connection status and latency in milliseconds
   */
  async healthCheck(): Promise<HealthCheckResult> {
    const startTime = performance.now();
    
    try {
      let connected = false;
      
      switch (this.config.type) {
        case 'splunk': {
          const response = await fetch(`${this.config.endpoint}/services/server/info`, {
            headers: {
              'Authorization': `Splunk ${this.config.apiKey}`
            }
          });
          connected = response.ok;
          break;
        }
        
        case 'datadog': {
          const response = await fetch(`${this.config.endpoint}/api/v1/validate`, {
            headers: {
              'DD-API-KEY': this.config.apiKey
            }
          });
          connected = response.ok;
          break;
        }
        
        case 'elastic': {
          const response = await fetch(`${this.config.endpoint}/_cluster/health`, {
            headers: {
              'Authorization': `ApiKey ${this.config.apiKey}`
            }
          });
          connected = response.ok;
          break;
        }
        
        case 'sentinel': {
          connected = !!this.config.workspaceId;
          break;
        }
      }
      
      const latencyMs = Math.round(performance.now() - startTime);
      return { connected, latencyMs };
      
    } catch (error) {
      return { connected: false, latencyMs: Math.round(performance.now() - startTime) };
    }
  }
}
