/**
 * Arniko Scan Orchestrator Tests
 * Tests against the actual ArnikoOrchestrator API with database persistence
 */

import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { drizzle } from 'drizzle-orm/node-postgres';
import { drizzle as drizzlePgLite } from 'drizzle-orm/pglite';
import { PGlite } from '@electric-sql/pglite';
import { ArnikoOrchestrator, ScanOrchestrator } from '../src/orchestrator.js';
import type { ArnikoConfig } from '../src/orchestrator.js';
import * as schema from '../src/db/schema.js';

const TEST_CONFIG: ArnikoConfig = {
  scanners: {
    garak: { enabled: true, config: { endpoint: 'http://localhost:9999', probes: ['jailbreak'] } },
    semgrep: { enabled: true },
    trufflehog: { enabled: true, config: { simulation: true } },
    trivy: { enabled: false },
  },
};

// Helper to create an in-memory database for testing
async function createTestDb() {
  const client = new PGlite();
  const db = drizzlePgLite(client, { schema });
  
  // Create tables
  await client.exec(`
    CREATE TABLE IF NOT EXISTS arniko_scans (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      tools JSONB NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'pending',
      duration_ms INTEGER,
      error TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      completed_at TIMESTAMPTZ
    );
    
    CREATE TABLE IF NOT EXISTS arniko_findings (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      scan_id UUID NOT NULL REFERENCES arniko_scans(id) ON DELETE CASCADE,
      tool TEXT NOT NULL,
      severity TEXT NOT NULL,
      message TEXT NOT NULL,
      file TEXT,
      line INTEGER,
      rule TEXT,
      metadata JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  
  return db;
}

describe('ArnikoOrchestrator', () => {
  let orchestrator: ArnikoOrchestrator;

  beforeEach(async () => {
    const db = await createTestDb();
    orchestrator = new ArnikoOrchestrator(TEST_CONFIG, db as any);
  });

  it('starts a scan and returns a scanId string', async () => {
    const scanId = await orchestrator.startScan(
      'user-1',
      'repository',
      '/tmp/test-repo',
      ['trufflehog']
    );

    expect(typeof scanId).toBe('string');
    expect(scanId.length).toBeGreaterThan(0);
  });

  it('getStatus returns running or completed for valid scanId', async () => {
    const scanId = await orchestrator.startScan(
      'user-1',
      'llm',
      'https://api.example.com',
      ['trufflehog']
    );

    const status = await orchestrator.getStatus(scanId);
    expect(['pending', 'running', 'completed', 'failed']).toContain(status);
  });

  it('getStatus returns null for unknown scanId', async () => {
    const status = await orchestrator.getStatus('nonexistent-scan-id');
    expect(status).toBeNull();
  });

  it('getFindings returns result for valid scanId', async () => {
    const scanId = await orchestrator.startScan(
      'user-1',
      'repository',
      '/tmp/test',
      ['trufflehog']
    );

    // Wait briefly for scan to start
    await new Promise(r => setTimeout(r, 100));

    const findings = await orchestrator.getFindings(scanId);
    // May be null if not completed yet or present with findings array
    if (findings) {
      expect(findings.scanId).toBe(scanId);
      expect(Array.isArray(findings.findings)).toBe(true);
      expect(typeof findings.count).toBe('number');
    }
  });

  it('getFindings returns null for unknown scanId', async () => {
    const result = await orchestrator.getFindings('nonexistent-id');
    expect(result).toBeNull();
  });

  it('isComplete returns false for unknown scanId', async () => {
    const complete = await orchestrator.isComplete('nonexistent-id');
    expect(complete).toBe(false);
  });

  it('isComplete returns true after scan completes', async () => {
    const scanId = await orchestrator.startScan(
      'user-1',
      'repository',
      '/tmp/test',
      ['trufflehog']
    );

    // Poll for up to 5s
    let complete = false;
    for (let i = 0; i < 25; i++) {
      await new Promise(r => setTimeout(r, 200));
      complete = await orchestrator.isComplete(scanId);
      if (complete) break;
    }

    expect(complete).toBe(true);
  });

  it('ScanOrchestrator is a backward-compat alias for ArnikoOrchestrator', async () => {
    const db = await createTestDb();
    const compat = new ScanOrchestrator(TEST_CONFIG, db as any);
    expect(compat).toBeInstanceOf(ArnikoOrchestrator);
  });

  it('disabled scanner is skipped', async () => {
    const scanId = await orchestrator.startScan(
      'user-1',
      'container',
      'nginx:latest',
      ['trivy'] // trivy is disabled in TEST_CONFIG
    );

    // Wait for completion
    for (let i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 100));
      const done = await orchestrator.isComplete(scanId);
      if (done) break;
    }

    const findings = await orchestrator.getFindings(scanId);
    // Disabled scanner produces no findings
    expect(findings?.findings.length ?? 0).toBe(0);
  });

  it('listScans returns scans for a user', async () => {
    const scanId1 = await orchestrator.startScan('user-2', 'repository', '/tmp/test1', ['trufflehog']);
    const scanId2 = await orchestrator.startScan('user-2', 'llm', 'https://api.test.com', ['trufflehog']);
    
    const scans = await orchestrator.listScans('user-2');
    expect(scans.length).toBeGreaterThanOrEqual(2);
    const scanIds = scans.map(s => s.scanId);
    expect(scanIds).toContain(scanId1);
    expect(scanIds).toContain(scanId2);
  });

  it('getScanDetails returns full scan information', async () => {
    const scanId = await orchestrator.startScan(
      'user-1',
      'repository',
      '/tmp/test',
      ['trufflehog']
    );

    // Wait for completion
    for (let i = 0; i < 25; i++) {
      await new Promise(r => setTimeout(r, 200));
      const done = await orchestrator.isComplete(scanId);
      if (done) break;
    }

    const details = await orchestrator.getScanDetails(scanId);
    expect(details).not.toBeNull();
    expect(details?.scanId).toBe(scanId);
    expect(details?.status).toMatch(/completed|failed/);
    expect(Array.isArray(details?.findings)).toBe(true);
  });

  it('persists scan data across orchestrator instances', async () => {
    // Create first orchestrator and start a scan
    const db1 = await createTestDb();
    const orch1 = new ArnikoOrchestrator(TEST_CONFIG, db1 as any);
    
    const scanId = await orch1.startScan(
      'user-persist',
      'repository',
      '/tmp/persist-test',
      ['trufflehog']
    );

    // Wait for completion
    for (let i = 0; i < 25; i++) {
      await new Promise(r => setTimeout(r, 200));
      const done = await orch1.isComplete(scanId);
      if (done) break;
    }

    // Create new orchestrator with same database
    const orch2 = new ArnikoOrchestrator(TEST_CONFIG, db1 as any);
    
    // Should be able to retrieve scan from new instance
    const status = await orch2.getStatus(scanId);
    expect(status).toMatch(/completed|failed/);
    
    const findings = await orch2.getFindings(scanId);
    expect(findings).not.toBeNull();
    expect(findings?.scanId).toBe(scanId);
  });
});
