/**
 * Project Arniko v2.0 — API Server
 * Hono.js REST server for AI & Supply-Chain Security Platform
 */

import * as fs from 'fs';
import * as path from 'path';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';

// Load .env if present using built-in Node 20.6+/22 API or zero-dependency parser (fixes Issue #2)
try {
  const envPath = path.resolve(process.cwd(), '.env');
  if (fs.existsSync(envPath)) {
    if (typeof (process as any).loadEnvFile === 'function') {
      (process as any).loadEnvFile(envPath);
    } else {
      for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx > 0) {
          const k = trimmed.slice(0, eqIdx).trim();
          const v = trimmed.slice(eqIdx + 1).trim().replace(/^['"]|['"]$/g, '');
          if (!(k in process.env)) process.env[k] = v;
        }
      }
    }
  }
} catch {
  // Ignore missing .env
}

import { createScanRoutes, createArnikoRoutes } from './api/routes.js';
import { createDashboardRoutes } from './api/dashboard.js';
import { ArnikoDb } from './db/client.js';

export const app = new Hono();

app.use('*', logger());
app.use('*', prettyJSON());
app.use(
  '/api/*',
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5177', 'http://localhost:3010'],
    credentials: true,
  })
);

app.get('/health', (c) =>
  c.json({
    status: 'ok',
    service: 'arniko',
    version: '0.2.0',
    engine: 'hybrid-ts-rust-lokahi-wasm',
    timestamp: new Date().toISOString(),
  })
);

app.route('/api/arniko/scans', createScanRoutes());
app.route('/api/arniko/dashboard', createDashboardRoutes());
app.route('/api/arniko', createArnikoRoutes());

const getDb = () =>
  process.env.ARNIKO_DATABASE_URL ? new ArnikoDb(process.env.ARNIKO_DATABASE_URL) : null;

app.get('/api/arniko/shield/events', async (c) => {
  const db = getDb();
  const userId = c.req.header('x-user-id') || 'anonymous';
  const events = db ? await db.getShieldEvents(userId, 50) : [];
  return c.json({ events, total: events.length });
});
app.get('/api/arniko/shield/metrics', (c) =>
  c.json({ totalRequests: 0, blockedRequests: 0, blockRate: 0 })
);
app.get('/api/arniko/risk/:userId', (c) =>
  c.json({ overall: 0, components: {}, trend: 'stable' })
);

export function startArnikoServer(port?: number) {
  const PORT = port ?? parseInt(process.env.ARNIKO_PORT || '3010', 10);
  return serve(
    {
      fetch: app.fetch,
      port: PORT,
    },
    (info) => {
      console.log(`[Arniko v0.2.0] Running on http://127.0.0.1:${info.port}`);
    }
  );
}

// Only start HTTP listener when executed directly (allows clean importing in tests/CLI)
const isDirectRun =
  process.argv[1] &&
  (process.argv[1].endsWith('server.js') || process.argv[1].endsWith('server.ts'));
if (isDirectRun) {
  startArnikoServer();
}

export default app;
