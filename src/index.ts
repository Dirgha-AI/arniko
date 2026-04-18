/**
 * @dirgha/arniko — AI Security Platform
 *
 * Main entry point. Exports all public APIs.
 */

export { ScanOrchestrator } from './orchestrator.js';
export { arnikoMiddleware } from './middleware/arnikoMiddleware.js';
export { createArnikoRoutes } from './api/routes.js';
export { GarakScanner, createGarakScanner } from './scanners/garak.js';
export { SemgrepScanner, createSemgrepScanner } from './scanners/semgrep.js';
export { TruffleHogScanner, createTruffleHogScanner } from './scanners/trufflehog.js';

export type {
  ArnikoConfig,
  ScanRequest,
  ScanResponse,
  ScanResult,
  ScanFinding,
  ScanTarget,
  ScanTool,
  ScanSeverity,
  ScanStatus,
  GarakConfig,
  GarakFinding,
  GarakProbe,
  SemgrepConfig,
  SemgrepFinding,
  TruffleHogConfig,
  TruffleHogFinding,
  ShieldEvent,
  ShieldMetrics,
  RiskScore,
  FindingsResponse,
} from './types/index.js';
