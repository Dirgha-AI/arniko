
import { ScanResult, ScanFinding } from '../types/index.js'

export interface SarifRule {
  id: string
  name: string
  shortDescription: { text: string }
  fullDescription?: { text: string }
  defaultConfiguration?: { level: 'error' | 'warning' | 'note' | 'none' }
  helpUri?: string
  properties?: { tags: string[] }
}

export interface SarifResult {
  ruleId: string
  level: 'error' | 'warning' | 'note' | 'none'
  message: { text: string }
  locations?: Array<{ physicalLocation: { artifactLocation: { uri: string }; region?: { startLine: number; startColumn?: number } } }>
  fingerprints?: Record<string, string>
  properties?: Record<string, unknown>
}

export interface SarifRun {
  tool: { driver: { name: string; version: string; informationUri: string; rules: SarifRule[] } }
  results: SarifResult[]
  properties?: { scanId: string; durationMs?: number }
}

export interface SarifDocument {
  version: '2.1.0'
  $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json'
  runs: SarifRun[]
}

export class SarifExporter {
  static severityToLevel(severity: string): 'error' | 'warning' | 'note' | 'none' {
    const s = severity.toLowerCase()
    if (s === 'critical' || s === 'high') return 'error'
    if (s === 'medium') return 'warning'
    if (s === 'low' || s === 'info') return 'note'
    return 'none'
  }

  static findingToRule(finding: ScanFinding): SarifRule {
    const id = finding.cwe ?? (finding.tool + '-' + finding.id.slice(0, 8))
    const name = finding.title.replace(/[^a-zA-Z0-9]/g, '')
    const level = this.severityToLevel(finding.severity)
    
    const rule: SarifRule = {
      id,
      name,
      shortDescription: { text: finding.title },
      fullDescription: { text: finding.description },
      defaultConfiguration: { level },
      properties: {
        tags: [finding.owasp, 'arniko', finding.tool].filter((t): t is string => Boolean(t))
      }
    }

    if (finding.cwe) {
      const cweNumber = finding.cwe.replace('CWE-', '')
      rule.helpUri = `https://cwe.mitre.org/data/definitions/${cweNumber}.html`
    }

    return rule
  }

  static findingToResult(finding: ScanFinding): SarifResult {
    const ruleId = finding.cwe ?? (finding.tool + '-' + finding.id.slice(0, 8))
    const level = this.severityToLevel(finding.severity)
    
    let text = finding.description
    if (finding.remediation) {
      text += '\n\nRemediation: ' + finding.remediation
    }

    const result: SarifResult = {
      ruleId,
      level,
      message: { text },
      fingerprints: {
        'arniko/v1': btoa(finding.title + finding.description)
      }
    }

    if (finding.metadata) {
      result.properties = finding.metadata
    }

    if (finding.location?.file) {
      const region: { startLine: number; startColumn?: number } = {
        startLine: finding.location.line || 1
      }
      
      if (finding.location.column) {
        region.startColumn = finding.location.column
      }

      result.locations = [{
        physicalLocation: {
          artifactLocation: {
            uri: finding.location.file
          },
          region
        }
      }]
    }

    return result
  }

  static export(scanResults: ScanResult[], options?: { toolVersion?: string }): SarifDocument {
    const runs: SarifRun[] = scanResults.map(scan => {
      const ruleMap = new Map<string, SarifRule>()
      const results: SarifResult[] = []

      for (const finding of scan.findings) {
        const rule = this.findingToRule(finding)
        if (!ruleMap.has(rule.id)) {
          ruleMap.set(rule.id, rule)
        }
        results.push(this.findingToResult(finding))
      }

      return {
        tool: {
          driver: {
            name: scan.tool,
            version: options?.toolVersion || '1.0.0',
            informationUri: 'https://arniko.dev',
            rules: Array.from(ruleMap.values())
          }
        },
        results,
        properties: {
          scanId: scan.scanId,
          durationMs: scan.durationMs
        }
      }
    })

    return {
      version: '2.1.0',
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs
    }
  }

  static toJson(doc: SarifDocument): string {
    return JSON.stringify(doc, null, 2)
  }

  static toBuffer(doc: SarifDocument): Buffer {
    return Buffer.from(this.toJson(doc), 'utf-8')
  }
}
