/**
 * Project Arniko — API Server
 * Hono.js REST + WebSocket server for AI security platform
 */

import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import 'dotenv/config';

// Import routes
import { createScanRoutes, createArnikoRoutes } from './api/routes.js';
import { createDashboardRoutes } from './api/dashboard.js';
import { ArnikoDb } from './db/client.js';

const app = new Hono();

// Middleware
app.use('*', logger());
app.use('*', prettyJSON());
app.use('/api/*', cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5177'],
  credentials: true,
}));

// Health check
app.get('/health', (c) => c.json({
  status: 'ok',
  service: 'arniko',
  version: '0.1.0',
  timestamp: new Date().toISOString()
}));

// Mount real API routes
app.route('/api/arniko/scans', createScanRoutes());
app.route('/api/arniko/dashboard', createDashboardRoutes());
// System-level routes (posture, coverage) mounted at /api/arniko
app.route('/api/arniko', createArnikoRoutes());

// Shield routes (backed by DB if configured)
const getDb = () => process.env.ARNIKO_DATABASE_URL ? new ArnikoDb(process.env.ARNIKO_DATABASE_URL) : null;
app.get('/api/arniko/shield/events', async (c) => {
  const db = getDb();
  const userId = c.req.header('x-user-id') || 'anonymous';
  const events = db ? await db.getShieldEvents(userId, 50) : [];
  return c.json({ events, total: events.length });
});
app.get('/api/arniko/shield/metrics', (c) => c.json({ totalRequests: 0, blockedRequests: 0, blockRate: 0 }));
app.get('/api/arniko/risk/:userId', (c) => c.json({ overall: 0, components: {}, trend: 'stable' }));

const PORT = parseInt(process.env.ARNIKO_PORT || '3010', 10);

serve({
  fetch: app.fetch,
  port: PORT,
}, (info) => {
  console.log(`[Arniko] Running on port ${info.port}`);
});

export default app;
