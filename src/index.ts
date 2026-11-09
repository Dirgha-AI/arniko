/**
 * @dirgha/arniko v0.2.0 — Hybrid Rust + TypeScript AI & Supply-Chain Security Platform
 *
 * Main entry point. Exports all public APIs.
 */

export { ScanOrchestrator, ArnikoOrchestrator } from './orchestrator.js';
export { arnikoMiddleware, SecurityShield } from './middleware/arnikoMiddleware.js';
export type { ShieldConfig, ShieldCheckResult, ShieldResponseFilterResult } from './middleware/arnikoMiddleware.js';
export { createArnikoRoutes, createScanRoutes } from './api/routes.js';
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
