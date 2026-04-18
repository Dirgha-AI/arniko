import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import * as path from 'path';
import type { ScanTarget, ScanResult, ScanFinding } from '../types/index.js';

export class CodeQLScanner {
  private config: {
    database?: string;
    language: 'javascript' | 'typescript' | 'python' | 'go' | 'java';
    querySuites: string[];
  };

  constructor(config: { 
    database?: string; 
    language: 'javascript' | 'typescript' | 'python' | 'go' | 'java'; 
    querySuites?: string[] 
  }) {
    this.config = {
      ...config,
      querySuites: config.querySuites || ['security-extended', 'security-and-quality']
    };
  }

  /**
   * Checks if the CodeQL CLI is installed and available in PATH
   */
  async checkInstalled(): Promise<boolean> {
    return new Promise((resolve) => {
      const child = spawn('codeql', ['--version']);
      child.on('error', () => resolve(false));
      child.on('close', (code) => resolve(code === 0));
    });
  }

  /**
   * Creates a CodeQL database for the target codebase
   */
  async createDatabase(sourcePath: string): Promise<string> {
    const dbPath = this.config.database || path.join(process.cwd(), `codeql-db-${Date.now()}`);
    
    return this.runCommand('codeql', [
      'database', 
      'create', 
      dbPath, 
      '--language', 
      this.config.language,
      '--source-root',
      sourcePath,
      '--overwrite'
    ]).then(() => dbPath);
  }

  /**
   * Runs CodeQL queries against a database and generates SARIF output
   */
  async runQueries(database: string, suite: string): Promise<string> {
    const outputPath = path.join(process.cwd(), `codeql-results-${suite.replace(/[^a-z0-9]/gi, '_')}.sarif`);
    
    await this.runCommand('codeql', [
      'database',
      'analyze',
      database,
      suite,
      '--format',
      'sarifv2.1.0',
      '--output',
      outputPath,
      '--sarif-add-snippets',
      '--no-sarif-add-file-contents'
    ]);
    
    return outputPath;
  }

  /**
   * Parses a SARIF file into an array of ScanFindings
   */
  async parseSARIF(sarifPath: string): Promise<ScanFinding[]> {
    try {
      const content = await fs.readFile(sarifPath, 'utf-8');
      const sarif = JSON.parse(content);
      
      const findings: ScanFinding[] = [];
      
      if (!sarif.runs || !Array.isArray(sarif.runs)) {
        return findings;
      }

      for (const run of sarif.runs) {
        if (!run.results || !Array.isArray(run.results)) continue;
        
        const ruleMap = new Map<number, string>();
        if (run.tool?.driver?.rules) {
          run.tool.driver.rules.forEach((rule: any, index: number) => {
            ruleMap.set(index, rule.id || rule.name);
          });
        }
        
        for (const result of run.results) {
          const ruleId = result.ruleId || 
                        (result.ruleIndex !== undefined && ruleMap.has(result.ruleIndex) 
                          ? ruleMap.get(result.ruleIndex) 
                          : 'unknown');
          
          const finding: any = {
            ruleId: ruleId,
            message: this.extractMessage(result),
            severity: this.mapSARIFLevel(result.level),
            location: this.extractLocation(result.locations),
            code: result.codeFlows ? 'has-flow' : undefined,
            metadata: {
              ruleIndex: result.ruleIndex,
              rule: run.tool?.driver?.rules?.[result.ruleIndex]
            }
          };
          findings.push(finding);
        }
      }
      
      return findings;
    } catch (error) {
      throw new Error(`Failed to parse SARIF file at ${sarifPath}: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Main execution method that orchestrates the full scan process
   */
  async run(target: ScanTarget): Promise<ScanResult> {
    const isInstalled = await this.checkInstalled();
    if (!isInstalled) {
      throw new Error('CodeQL CLI is not installed or not available in PATH. Please install CodeQL CLI.');
    }

    const dbPath = await this.createDatabase(target.identifier);

    const allFindings: ScanFinding[] = [];
    const sarifFiles: string[] = [];
    const errors: string[] = [];

    for (const suite of this.config.querySuites) {
      try {
        const sarifPath = await this.runQueries(dbPath, suite);
        sarifFiles.push(sarifPath);
        
        const findings = await this.parseSARIF(sarifPath);
        allFindings.push(...findings);
      } catch (error) {
        const errorMsg = `Suite ${suite} failed: ${error instanceof Error ? error.message : 'Unknown error'}`;
        console.warn(errorMsg);
        errors.push(errorMsg);
      }
    }

    const summary = {
      total: allFindings.length,
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high: allFindings.filter(f => f.severity === 'high').length,
      medium: allFindings.filter(f => f.severity === 'medium').length,
      low: allFindings.filter(f => f.severity === 'low').length,
      info: allFindings.filter(f => f.severity === 'info').length
    };

    return {
      target,
      findings: allFindings,
      summary,
      metadata: {
        tool: 'codeql',
        language: this.config.language,
        querySuites: this.config.querySuites,
        databasePath: dbPath,
        sarifFiles,
        errors: errors.length > 0 ? errors : undefined,
        timestamp: new Date().toISOString()
      }
    } as unknown as ScanResult;
  }

  /**
   * Generates a mock scan result for testing purposes
   */
  simulateScan(): ScanResult {
    const mockFindings: any[] = [
      {
        ruleId: 'js/sql-injection',
        message: 'Potential SQL injection vulnerability detected in database query',
        severity: 'high',
        location: {
          file: 'src/database.js',
          line: 42,
          column: 15
        },
        metadata: { simulated: true }
      },
      {
        ruleId: 'js/xss',
        message: 'Cross-site scripting vulnerability in user input rendering',
        severity: 'medium',
        location: {
          file: 'src/views/user.html',
          line: 23,
          column: 8
        },
        metadata: { simulated: true }
      },
      {
        ruleId: 'js/hardcoded-credentials',
        message: 'Hardcoded credentials detected in configuration',
        severity: 'critical',
        location: {
          file: 'src/config/auth.js',
          line: 5,
          column: 20
        },
        metadata: { simulated: true }
      }
    ];

    return {
      target: {
        path: '/mock/project/path',
        language: this.config.language
      } as unknown as ScanTarget,
      findings: mockFindings,
      summary: {
        total: 3,
        critical: 1,
        high: 1,
        medium: 1,
        low: 0,
        info: 0
      },
      metadata: {
        tool: 'codeql',
        language: this.config.language,
        querySuites: this.config.querySuites,
        simulated: true,
        timestamp: new Date().toISOString()
      }
    } as unknown as ScanResult;
  }

  private runCommand(command: string, args: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const child = spawn(command, args);
      
      let stderr = '';
      let stdout = '';
      
      child.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      child.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      child.on('close', (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Command failed with code ${code}: ${stderr || stdout}`));
        }
      });

      child.on('error', (err) => {
        reject(new Error(`Failed to spawn ${command}: ${err.message}`));
      });
    });
  }

  private mapSARIFLevel(level?: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    switch (level?.toLowerCase()) {
      case 'error': return 'high';
      case 'warning': return 'medium';
      case 'note': return 'low';
      case 'none': return 'info';
      default: return 'medium';
    }
  }

  private extractMessage(result: any): string {
    if (typeof result.message === 'string') return result.message;
    if (result.message?.text) return result.message.text;
    if (result.message?.markdown) return result.message.markdown;
    return 'No message provided';
  }

  private extractLocation(locations?: any[]): { file: string; line: number; column: number; endLine?: number; endColumn?: number } | undefined {
    if (!locations || !Array.isArray(locations) || locations.length === 0) {
      return undefined;
    }
    
    const location = locations[0].physicalLocation;
    if (!location) return undefined;
    
    const region = location.region;
    
    return {
      file: location.artifactLocation?.uri || 'unknown',
      line: region?.startLine || 0,
      column: region?.startColumn || 0,
      endLine: region?.endLine,
      endColumn: region?.endColumn
    };
  }
}