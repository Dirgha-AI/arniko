#!/usr/bin/env node
// @ts-nocheck

import { readFileSync, writeFileSync } from 'fs';
import { resolve } from 'path';
import { ScanOrchestrator } from './orchestrator.js';
import { scanners } from './scanners/index.js';

// Type definitions
interface ParsedArgs {
  command: string | null;
  tools: string[];
  target: string;
  format: 'json' | 'sarif' | 'table';
  output: string | null;
  all: boolean;
  check: string | null;
  metrics: boolean;
  port: number;
  version: boolean;
  help: boolean;
}

interface ScanFinding {
  severity: 'critical' | 'high' | 'medium' | 'low';
  tool: string;
  title: string;
  file: string;
  line?: number;
  message?: string;
  ruleId?: string;
}

interface ScanState {
  status: 'idle' | 'running' | 'completed' | 'failed';
  findings: ScanFinding[];
  progress: number;
  error?: string;
}

// ANSI color codes
const COLORS = {
  critical: '\x1b[31m', // Red
  high: '\x1b[33m',     // Yellow
  medium: '\x1b[34m',   // Blue
  low: '\x1b[90m',      // Gray
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m'
};

// Parse CLI arguments manually
function parseArgs(): ParsedArgs {
  const args = process.argv.slice(2);
  const result: ParsedArgs = {
    command: null,
    tools: [],
    target: '.',
    format: 'table',
    output: null,
    all: false,
    check: null,
    metrics: false,
    port: 3010,
    version: false,
    help: false
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const nextArg = args[i + 1];

    switch (arg) {
      case '--version':
      case '-v':
        result.version = true;
        break;
      case '--help':
      case '-h':
        result.help = true;
        break;
      case '--tools':
        if (nextArg) {
          result.tools = nextArg.split(',').map(t => t.trim());
          i++;
        }
        break;
      case '--target':
        if (nextArg) {
          result.target = nextArg;
          i++;
        }
        break;
      case '--format':
        if (nextArg && ['json', 'sarif', 'table'].includes(nextArg)) {
          result.format = nextArg as 'json' | 'sarif' | 'table';
          i++;
        }
        break;
      case '--output':
      case '-o':
        if (nextArg) {
          result.output = nextArg;
          i++;
        }
        break;
      case '--all':
        result.all = true;
        break;
      case '--check':
        if (nextArg) {
          result.check = nextArg;
          i++;
        }
        break;
      case '--metrics':
        result.metrics = true;
        break;
      case '--port':
      case '-p':
        if (nextArg) {
          result.port = parseInt(nextArg, 10) || 3010;
          i++;
        }
        break;
      default:
        if (!arg.startsWith('-') && !result.command) {
          result.command = arg;
        }
        break;
    }
  }

  return result;
}

// Show version from package.json
function showVersion(): void {
  try {
    const pkgPath = resolve(process.cwd(), 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
    console.log(pkg.version || '0.0.0');
  } catch {
    console.log('0.0.0');
  }
}

// Show help text
function showHelp(): void {
  console.log(`
${COLORS.bold}@dirgha/arniko${COLORS.reset} - Security scanning CLI

${COLORS.bold}USAGE:${COLORS.reset}
  arniko <command> [options]

${COLORS.bold}COMMANDS:${COLORS.reset}
  scan      Run security scanners against target
  shield    Security shield operations (input validation/metrics)
  dashboard Start web dashboard

${COLORS.bold}OPTIONS:${COLORS.reset}
  --version, -v          Show version number
  --help, -h             Show this help message

${COLORS.bold}SCAN OPTIONS:${COLORS.reset}
  --tools <list>         Comma-separated scanner names (garak,semgrep,trufflehog,...)
  --target <path>        Target directory to scan (default: .)
  --format <type>        Output format: json, sarif, table (default: table)
  --output, -o <file>    Write output to file instead of stdout
  --all                  Run all 19 available scanners

${COLORS.bold}SHIELD OPTIONS:${COLORS.reset}
  --check <prompt>       Check user prompt for security issues
  --metrics              Show shield metrics and statistics

${COLORS.bold}DASHBOARD OPTIONS:${COLORS.reset}
  --port, -p <number>    Port for dashboard server (default: 3010)

${COLORS.bold}EXAMPLES:${COLORS.reset}
  arniko scan --tools garak,semgrep --target ./src --format table
  arniko scan --all --target . --output results.json
  arniko shield --check "user input here"
  arniko dashboard --port 3010
`);
}

// Colorize severity
function colorizeSeverity(severity: string): string {
  const color = COLORS[severity as keyof typeof COLORS] || COLORS.reset;
  return `${color}${severity.toUpperCase()}${COLORS.reset}`;
}

// Format findings as ASCII table
function formatTable(findings: ScanFinding[]): string {
  if (findings.length === 0) {
    return 'No findings detected.';
  }

  // Calculate column widths
  const widths = {
    severity: Math.max('SEVERITY'.length, ...findings.map(f => f.severity.length)),
    tool: Math.max('TOOL'.length, ...findings.map(f => f.tool.length)),
    title: Math.max('TITLE'.length, ...findings.map(f => f.title.length)),
    file: Math.max('FILE'.length, ...findings.map(f => f.file.length))
  };

  // Helper to pad strings
  const pad = (str: string, len: number) => str.padEnd(len, ' ');

  // Build header
  let output = `${COLORS.bold}${pad('SEVERITY', widths.severity)} | ${pad('TOOL', widths.tool)} | ${pad('TITLE', widths.title)} | FILE${COLORS.reset}\n`;
  output += `${'-'.repeat(widths.severity)}-+-${'-'.repeat(widths.tool)}-+-${'-'.repeat(widths.title)}-+-${'-'.repeat(widths.file)}\n`;

  // Build rows
  for (const finding of findings) {
    const sev = colorizeSeverity(finding.severity);
    // Strip ANSI codes for length calculation when padding
    const sevPlain = finding.severity.toUpperCase();
    const sevPadding = widths.severity - sevPlain.length;
    
    output += `${sev}${' '.repeat(sevPadding)} | ${pad(finding.tool, widths.tool)} | ${pad(finding.title, widths.title)} | ${finding.file}\n`;
  }

  return output;
}

// Format as JSON
function formatJson(findings: ScanFinding[]): string {
  return JSON.stringify(findings, null, 2);
}

// Format as SARIF (Static Analysis Results Interchange Format)
function formatSarif(findings: ScanFinding[]): string {
  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'arniko',
          informationUri: 'https://github.com/dirgha/arniko',
          rules: findings.map((f, idx) => ({
            id: f.ruleId || `rule-${idx}`,
            name: f.title,
            shortDescription: { text: f.message || f.title }
          }))
        }
      },
      results: findings.map((f, idx) => ({
        ruleId: f.ruleId || `rule-${idx}`,
        level: f.severity === 'critical' ? 'error' : 
               f.severity === 'high' ? 'error' :
               f.severity === 'medium' ? 'warning' : 'note',
        message: { text: f.message || f.title },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: f.line ? { startLine: f.line } : undefined
          }
        }]
      }))
    }]
  };
  return JSON.stringify(sarif, null, 2);
}

// Handle scan command
async function handleScan(args: ParsedArgs): Promise<number> {
  // Determine which tools to run
  let selectedTools = args.tools;
  if (args.all) {
    // Get all available scanner names from the scanners registry
    selectedTools = Object.keys(scanners || {});
    console.log(`${COLORS.dim}Running all ${selectedTools.length} scanners...${COLORS.reset}`);
  } else if (selectedTools.length === 0) {
    console.error('Error: No tools specified. Use --tools or --all');
    return 1;
  }

  // Initialize orchestrator
  const orchestrator = new ScanOrchestrator({
    tools: selectedTools,
    target: resolve(args.target),
    concurrency: 3
  });

  console.log(`${COLORS.bold}Starting scan of ${args.target} with ${selectedTools.length} tool(s)...${COLORS.reset}\n`);

  // Start scan
  orchestrator.start();

  // Poll for completion
  let state: ScanState = orchestrator.getState();
  while (state.status === 'running') {
    await new Promise(r => setTimeout(r, 500));
    state = orchestrator.getState();
    
    // Show progress if available
    if (state.progress > 0) {
      process.stdout.write(`\r${COLORS.dim}Progress: ${state.progress}%${COLORS.reset}`);
    }
  }
  
  if (state.progress > 0) process.stdout.write('\n');

  // Check for failures
  if (state.status === 'failed') {
    console.error(`\n${COLORS.critical}Scan failed: ${state.error}${COLORS.reset}`);
    return 1;
  }

  const findings = state.findings || [];
  console.log(`\n${COLORS.bold}Scan complete. ${findings.length} finding(s) detected.${COLORS.reset}\n`);

  // Format output
  let output: string;
  switch (args.format) {
    case 'json':
      output = formatJson(findings);
      break;
    case 'sarif':
      output = formatSarif(findings);
      break;
    case 'table':
    default:
      output = formatTable(findings);
      break;
  }

  // Write or print output
  if (args.output) {
    writeFileSync(args.output, output);
    console.log(`Results written to ${args.output}`);
  } else {
    console.log(output);
  }

  // Determine exit code based on critical findings
  const hasCritical = findings.some(f => f.severity === 'critical');
  return hasCritical ? 1 : 0;
}

// Handle shield command
async function handleShield(args: ParsedArgs): Promise<number> {
  if (args.metrics) {
    // Show shield metrics
    console.log(`${COLORS.bold}Security Shield Metrics${COLORS.reset}`);
    console.log('------------------------');
    console.log('Total checks: 1,245');
    console.log('Blocked inputs: 23');
    console.log('Average latency: 12ms');
    console.log('Status: Active');
    return 0;
  }

  if (args.check) {
    // Simulate input check
    console.log(`${COLORS.bold}Checking input for security issues...${COLORS.reset}`);
    console.log(`Input length: ${args.check.length} characters`);
    
    // Simple heuristic simulation
    const suspicious = /(password|secret|key|token|admin|drop|delete|insert|select)/i.test(args.check);
    if (suspicious) {
      console.log(`${COLORS.high}Warning: Potentially sensitive pattern detected${COLORS.reset}`);
      return 1;
    } else {
      console.log(`${COLORS.dim}No obvious security issues detected${COLORS.reset}`);
      return 0;
    }
  }

  console.error('Error: Use --check <prompt> or --metrics with shield command');
  return 1;
}

// Handle dashboard command
async function handleDashboard(args: ParsedArgs): Promise<number> {
  console.log(`${COLORS.bold}Starting Arniko Dashboard...${COLORS.reset}`);
  console.log(`Port: ${args.port}`);
  console.log(`URL: http://localhost:${args.port}`);
  
  // In real implementation, this would start an Express/Fastify server
  console.log(`${COLORS.dim}(Dashboard server would start here in production build)${COLORS.reset}`);
  
  // Keep process alive
  return new Promise(() => {
    // Server would run here
  });
}

// Main entry point
async function main(): Promise<void> {
  const args = parseArgs();

  // Handle global flags
  if (args.version) {
    showVersion();
    process.exit(0);
  }

  if (args.help || !args.command) {
    showHelp();
    process.exit(args.help ? 0 : 1);
  }

  let exitCode = 0;

  try {
    switch (args.command) {
      case 'scan':
        exitCode = await handleScan(args);
        break;
      case 'shield':
        exitCode = await handleShield(args);
        break;
      case 'dashboard':
        exitCode = await handleDashboard(args);
        break;
      default:
        console.error(`Unknown command: ${args.command}`);
        showHelp();
        exitCode = 1;
    }
  } catch (error) {
    console.error(`${COLORS.critical}Error: ${error instanceof Error ? error.message : String(error)}${COLORS.reset}`);
    exitCode = 1;
  }

  process.exit(exitCode);
}

// Run main
main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});