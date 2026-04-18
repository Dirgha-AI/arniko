import { spawn } from 'child_process';
import { randomUUID } from 'crypto';
import type { ScanResult, ScanFinding, ScanSeverity, ScanTarget } from '../types/index.js';

/**
 * Bandit configuration options.
 */
interface BanditConfig {
  severity?: ('low' | 'medium' | 'high')[];
  confidence?: ('low' | 'medium' | 'high')[];
  skipTests?: string[];
  includeTests?: string[];
  profile?: string;
}

/**
 * Bandit JSON output structure.
 */
interface BanditResult {
  issue_severity: 'LOW' | 'MEDIUM' | 'HIGH';
  issue_confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  issue_text: string;
  filename: string;
  line_number: number;
  column_number?: number;
  test_id: string;
  test_name: string;
  code: string;
  more_info: string;
}

interface BanditMetrics {
  loc: number;
  nosec: number;
  skipped_tests: number;
}

interface BanditOutput {
  errors: Array<{ filename: string; reason: string }>;
  results: BanditResult[];
  metrics: {
    [key: string]: BanditMetrics;
    _totals: BanditMetrics;
  };
}

/**
 * Bandit security scanner adapter for Python codebases.
 * Wraps the PyCQA Bandit CLI to perform static security analysis.
 * 
 * Production-ready implementation with:
 * - Comprehensive error handling and timeout management
 * - Proper severity and confidence level filtering
 * - Standardized finding output
 * - Metrics tracking
 */
export class BanditScanner {
  private config: BanditConfig;
  private readonly DEFAULT_TIMEOUT = 120000; // 2 minutes

  constructor(config: BanditConfig = {}) {
    this.config = {
      severity: ['low', 'medium', 'high'],
      confidence: ['low', 'medium', 'high'],
      ...config
    };
  }

  /**
   * Executes a security scan against the provided Python codebase target.
   * 
   * @param {ScanTarget} target - The target to scan (must be type 'codebase')
   * @returns {Promise<ScanResult>} Promise resolving to standardized scan results
   */
  async run(target: ScanTarget): Promise<ScanResult> {
    const startedAt = new Date();
    const scanId = randomUUID();

    try {
      // Validate target
      if (target.type !== 'codebase') {
        throw new Error(`Bandit only supports 'codebase' target type, received: ${target.type}`);
      }

      const isInstalled = await this.checkInstalled();
      
      if (!isInstalled) {
        return this.createErrorResult(
          scanId, 
          target, 
          startedAt, 
          'Bandit is not installed. Install with: pip install bandit'
        );
      }

      const targetPath = target.identifier;
      const rawOutput = await this.runCLI(targetPath);
      const banditOutput: BanditOutput = JSON.parse(rawOutput);
      
      const findings = this.parseResults(banditOutput);
      const completedAt = new Date();

      return {
        scanId,
        status: 'completed',
        tool: 'bandit',
        target,
        findings,
        startedAt,
        completedAt,
        durationMs: completedAt.getTime() - startedAt.getTime(),
        metadata: {
          totalResults: banditOutput.results.length,
          totalErrors: banditOutput.errors.length,
          linesOfCode: banditOutput.metrics._totals?.loc,
          nosecCount: banditOutput.metrics._totals?.nosec,
          skippedTests: banditOutput.metrics._totals?.skipped_tests,
          severityFilter: this.config.severity,
          confidenceFilter: this.config.confidence,
        }
      };
    } catch (error) {
      const completedAt = new Date();
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      return {
        scanId,
        status: 'failed',
        tool: 'bandit',
        target,
        findings: [],
        startedAt,
        completedAt,
        durationMs: completedAt.getTime() - startedAt.getTime(),
        error: errorMessage,
      };
    }
  }

  /**
   * Verifies that the Bandit CLI is installed and accessible.
   * 
   * @returns {Promise<boolean>} True if Bandit is installed
   */
  async checkInstalled(): Promise<boolean> {
    return new Promise((resolve) => {
      const proc = spawn('bandit', ['--version'], { timeout: 10000 });
      let timedOut = false;

      const timeout = setTimeout(() => {
        timedOut = true;
        proc.kill();
        resolve(false);
      }, 10000);

      proc.on('error', () => {
        clearTimeout(timeout);
        resolve(false);
      });

      proc.on('close', (code) => {
        clearTimeout(timeout);
        if (timedOut) return;
        resolve(code === 0);
      });
    });
  }

  /**
   * Executes the Bandit CLI command with appropriate arguments.
   * 
   * @param {string} targetPath - Path to the Python codebase
   * @returns {Promise<string>} Raw JSON output from Bandit
   */
  private runCLI(targetPath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const args: string[] = [
        '-r', // Recursive
        targetPath,
        '-f', 'json', // JSON format
        '-ii', // Include more info (line numbers, etc.)
      ];

      // Configure severity level filtering
      if (this.config.severity && this.config.severity.length > 0) {
        // Map to bandit's severity levels
        const severityMap: Record<string, string> = {
          'low': 'low',
          'medium': 'medium',
          'high': 'high'
        };

        // Find the minimum severity level to report
        const levels = ['low', 'medium', 'high'];
        let minLevel: string | null = null;
        
        for (const level of levels) {
          if (this.config.severity!.includes(level as any)) {
            minLevel = severityMap[level] ?? null;
            break;
          }
        }
        
        if (minLevel) {
          args.push('-l', minLevel); // --level
        }
      }

      // Configure confidence level filtering
      if (this.config.confidence && this.config.confidence.length > 0) {
        const confidenceMap: Record<string, string> = {
          'low': 'low',
          'medium': 'medium',
          'high': 'high'
        };

        const levels = ['low', 'medium', 'high'];
        let minConfidence: string | null = null;
        
        for (const level of levels) {
          if (this.config.confidence!.includes(level as any)) {
            minConfidence = confidenceMap[level] ?? null;
            break;
          }
        }
        
        if (minConfidence) {
          args.push('-c', minConfidence); // --confidence
        }
      }

      // Skip specific tests if configured
      if (this.config.skipTests && this.config.skipTests.length > 0) {
        args.push('-s', this.config.skipTests.join(',')); // --skip
      }

      // Include only specific tests if configured
      if (this.config.includeTests && this.config.includeTests.length > 0) {
        args.push('-t', this.config.includeTests.join(',')); // --tests
      }

      // Use profile if configured
      if (this.config.profile) {
        args.push('-p', this.config.profile); // --profile
      }

      const proc = spawn('bandit', args, {
        timeout: this.DEFAULT_TIMEOUT,
        killSignal: 'SIGTERM'
      });

      let stdout = '';
      let stderr = '';
      let timedOut = false;

      proc.stdout.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      proc.on('error', (error) => {
        reject(new Error(`Failed to execute Bandit: ${error.message}`));
      });

      proc.on('close', (code, signal) => {
        if (timedOut) return;

        // Handle timeout
        if (signal === 'SIGTERM') {
          reject(new Error('Bandit scan timed out after 2 minutes'));
          return;
        }

        // Bandit exit codes:
        // 0 - No issues found
        // 1 - Issues found (this is success for us)
        // Other codes indicate errors
        if (code !== 0 && code !== 1) {
          reject(new Error(`Bandit exited with code ${code}: ${stderr || 'Unknown error'}`));
        } else {
          resolve(stdout);
        }
      });
    });
  }

  /**
   * Parses Bandit JSON output into standardized ScanFinding objects.
   * 
   * @param {BanditOutput} output - Parsed Bandit JSON output
   * @returns {ScanFinding[]} Array of standardized findings
   */
  private parseResults(output: BanditOutput): ScanFinding[] {
    if (!output.results || !Array.isArray(output.results)) {
      return [];
    }

    return output.results.map((result) => {
      // Map test ID to CWE where applicable
      const cwe = this.mapTestToCWE(result.test_id);
      
      return {
        id: `${result.test_id}-${randomUUID()}`,
        tool: 'bandit',
        severity: this.mapSeverity(result.issue_severity),
        title: `${result.test_name} (${result.test_id})`,
        description: result.issue_text,
        remediation: this.getRemediation(result.test_id),
        evidence: result.code,
        location: {
          file: result.filename,
          line: result.line_number,
          column: result.column_number,
        },
        cwe,
        owasp: this.mapTestToOWASP(result.test_id),
        metadata: {
          testId: result.test_id,
          testName: result.test_name,
          confidence: result.issue_confidence,
          moreInfo: result.more_info,
          code: result.code,
        }
      };
    });
  }

  /**
   * Maps Bandit severity levels to standardized ScanSeverity.
   */
  private mapSeverity(severity: string): ScanSeverity {
    const normalized = severity.toUpperCase();
    switch (normalized) {
      case 'HIGH':
        return 'high';
      case 'MEDIUM':
        return 'medium';
      case 'LOW':
        return 'low';
      default:
        return 'info';
    }
  }

  /**
   * Maps Bandit test IDs to CWE classifications.
   */
  private mapTestToCWE(testId: string): string | undefined {
    const cweMap: Record<string, string> = {
      'B102': 'CWE-78',   // exec_used
      'B103': 'CWE-22',   // set_bad_file_permissions
      'B104': 'CWE-78',   // hardcoded_bind_all_interfaces
      'B105': 'CWE-798',  // hardcoded_password_string
      'B106': 'CWE-798',  // hardcoded_password_funcarg
      'B107': 'CWE-798',  // hardcoded_password_default
      'B108': 'CWE-502',  // hardcoded_tmp_directory
      'B110': 'CWE-730',  // try_except_pass
      'B112': 'CWE-20',   // try_except_continue
      'B201': 'CWE-78',   // flask_debug_true
      'B301': 'CWE-502',  // pickle
      'B302': 'CWE-78',   // marshal
      'B303': 'CWE-78',   // md5, sha1
      'B304': 'CWE-89',   // ciphers
      'B305': 'CWE-327',  // cipher_modes
      'B306': 'CWE-295',  // mktemp_q
      'B307': 'CWE-78',   // eval
      'B308': 'CWE-89',   // mark_safe
      'B309': 'CWE-78',   // httpsconnection
      'B310': 'CWE-22',   // urllib_urlopen
      'B311': 'CWE-338',  // random
      'B312': 'CWE-78',   // telnetlib
      'B313': 'CWE-78',   // xml_bad_cElementTree
      'B314': 'CWE-78',   // xml_bad_ElementTree
      'B315': 'CWE-78',   // xml_bad_expatreader
      'B316': 'CWE-78',   // xml_bad_expatbuilder
      'B317': 'CWE-78',   // xml_bad_sax
      'B318': 'CWE-78',   // xml_bad_minidom
      'B319': 'CWE-78',   // xml_bad_pulldom
      'B320': 'CWE-78',   // xml_bad_etree
      'B321': 'CWE-78',   // ftplib
      'B322': 'CWE-78',   // input
      'B323': 'CWE-295',  // unverified_context
      'B324': 'CWE-327',  // hashlib_new_insecure_functions
      'B325': 'CWE-502',  // tempnam
      'B401': 'CWE-502',  // import_telnetlib
      'B402': 'CWE-78',   // import_ftplib
      'B403': 'CWE-502',  // import_pickle
      'B404': 'CWE-78',   // import_subprocess
      'B405': 'CWE-78',   // import_xml_etree
      'B406': 'CWE-78',   // import_xml_sax
      'B407': 'CWE-78',   // import_xml_expat
      'B408': 'CWE-78',   // import_xml_minidom
      'B409': 'CWE-78',   // import_xml_pulldom
      'B410': 'CWE-78',   // import_lxml
      'B411': 'CWE-78',   // import_xmlrpclib
      'B412': 'CWE-918',  // import_httpoxy
      'B413': 'CWE-327',  // import_pycrypto
      'B414': 'CWE-295',  // import_ssl
      'B501': 'CWE-295',  // request_with_no_cert_validation
      'B502': 'CWE-327',  // ssl_with_bad_version
      'B503': 'CWE-327',  // ssl_with_bad_defaults
      'B504': 'CWE-295',  // ssl_with_no_version
      'B505': 'CWE-326',  // weak_cryptographic_key
      'B506': 'CWE-295',  // yaml_load
      'B507': 'CWE-295',  // ssh_no_host_key_verification
      'B601': 'CWE-78',   // paramiko_calls
      'B602': 'CWE-78',   // subprocess_popen_with_shell
      'B603': 'CWE-78',   // subprocess_without_shell_equals_true
      'B604': 'CWE-78',   // any_other_function_with_shell_equals_true
      'B605': 'CWE-78',   // start_process_with_a_shell
      'B606': 'CWE-78',   // start_process_with_no_shell
      'B607': 'CWE-78',   // start_process_with_partial_path
      'B608': 'CWE-89',   // hardcoded_sql_expressions
      'B609': 'CWE-78',   // linux_commands_wildcard_injection
      'B610': 'CWE-91',   // django_extra_used
      'B611': 'CWE-89',   // django_rawsql_used
      'B612': 'CWE-89',   // django_mark_safe
      'B701': 'CWE-94',   // jinja2_autoescape_false
      'B702': 'CWE-78',   // use_of_mako_templates
      'B703': 'CWE-79',   // django_autoescape_off
    };
    
    return cweMap[testId];
  }

  /**
   * Maps Bandit test IDs to OWASP Top 10 categories.
   */
  private mapTestToOWASP(testId: string): string | undefined {
    const owaspMap: Record<string, string> = {
      'B608': 'A03:2021 – Injection',
      'B609': 'A03:2021 – Injection',
      'B610': 'A03:2021 – Injection',
      'B611': 'A03:2021 – Injection',
      'B612': 'A03:2021 – Injection',
      'B105': 'A07:2021 – Identification and Authentication Failures',
      'B106': 'A07:2021 – Identification and Authentication Failures',
      'B107': 'A07:2021 – Identification and Authentication Failures',
      'B703': 'A03:2021 – Injection',
      'B701': 'A03:2021 – Injection',
      'B702': 'A03:2021 – Injection',
      'B102': 'A04:2021 – Insecure Design',
      'B307': 'A03:2021 – Injection',
      'B602': 'A03:2021 – Injection',
      'B603': 'A03:2021 – Injection',
      'B604': 'A03:2021 – Injection',
      'B605': 'A03:2021 – Injection',
      'B606': 'A03:2021 – Injection',
      'B310': 'A01:2021 – Broken Access Control',
      'B301': 'A08:2021 – Software and Data Integrity Failures',
      'B501': 'A02:2021 – Cryptographic Failures',
      'B502': 'A02:2021 – Cryptographic Failures',
      'B503': 'A02:2021 – Cryptographic Failures',
      'B504': 'A02:2021 – Cryptographic Failures',
      'B505': 'A02:2021 – Cryptographic Failures',
    };
    
    return owaspMap[testId];
  }

  /**
   * Provides remediation guidance for specific test IDs.
   */
  private getRemediation(testId: string): string | undefined {
    const remediationMap: Record<string, string> = {
      'B102': 'Avoid using exec(). Use safer alternatives like ast.literal_eval() for evaluating expressions.',
      'B105': 'Remove hardcoded passwords. Use environment variables or a secure secrets manager.',
      'B106': 'Remove hardcoded passwords from function arguments. Use secure configuration.',
      'B107': 'Remove hardcoded passwords from default arguments. Use environment variables.',
      'B110': 'Do not use bare except/pass. Catch specific exceptions and handle them appropriately.',
      'B112': 'Do not use bare except/continue. Catch specific exceptions and handle them appropriately.',
      'B301': 'Avoid pickle for serialization. Use json or safer alternatives like marshmallow.',
      'B307': 'Avoid eval(). Use ast.literal_eval() for safe expression evaluation or refactor logic.',
      'B310': 'Validate and sanitize URLs. Use allowlists for acceptable schemes and domains.',
      'B608': 'Use parameterized queries or ORM instead of string formatting for SQL.',
      'B609': 'Sanitize command arguments. Avoid shell=True when possible.',
      'B701': 'Always set autoescape=True in Jinja2 environments.',
      'B501': 'Enable certificate verification in HTTP requests. Never set verify=False in production.',
    };
    
    return remediationMap[testId] || `Review Bandit documentation for test ${testId} at https://bandit.readthedocs.io/`;
  }

  /**
   * Creates a failed scan result with error information.
   */
  private createErrorResult(
    scanId: string,
    target: ScanTarget,
    startedAt: Date,
    errorMessage: string
  ): ScanResult {
    const completedAt = new Date();
    return {
      scanId,
      status: 'failed',
      tool: 'bandit',
      target,
      findings: [],
      startedAt,
      completedAt,
      durationMs: completedAt.getTime() - startedAt.getTime(),
      error: errorMessage,
    };
  }
}

/**
 * Factory function to create a BanditScanner instance.
 * 
 * @param {BanditConfig} config - Configuration for the Bandit scanner
 * @returns {BanditScanner} Configured BanditScanner instance
 */
export function createBanditScanner(config: BanditConfig = {}): BanditScanner {
  return new BanditScanner(config);
}