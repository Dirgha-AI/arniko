-- Project Arniko — Database Schema
-- Run against Neon Postgres (arniko database)
-- 2026-04-07

-- Scan sessions
CREATE TABLE IF NOT EXISTS arniko_scans (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     TEXT NOT NULL,
  app_id      TEXT,
  status      TEXT NOT NULL DEFAULT 'pending',  -- pending|running|completed|failed|cancelled
  target_type TEXT NOT NULL,                     -- llm_endpoint|codebase|container|config
  target_id   TEXT NOT NULL,
  tools       TEXT[] NOT NULL,                   -- which scanners were requested
  started_at  TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  duration_ms INTEGER,
  error       TEXT,
  metadata    JSONB DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX arniko_scans_user_id ON arniko_scans(user_id);
CREATE INDEX arniko_scans_status  ON arniko_scans(status);
CREATE INDEX arniko_scans_created ON arniko_scans(created_at DESC);

-- Individual findings per scan
CREATE TABLE IF NOT EXISTS arniko_findings (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id      UUID NOT NULL REFERENCES arniko_scans(id) ON DELETE CASCADE,
  tool         TEXT NOT NULL,
  severity     TEXT NOT NULL,   -- critical|high|medium|low|info
  title        TEXT NOT NULL,
  description  TEXT NOT NULL,
  remediation  TEXT,
  evidence     TEXT,
  location     JSONB DEFAULT '{}'::jsonb,
  cwe          TEXT,
  owasp        TEXT,
  resolved     BOOLEAN DEFAULT false,
  resolved_at  TIMESTAMPTZ,
  resolved_by  TEXT,
  metadata     JSONB DEFAULT '{}'::jsonb,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX arniko_findings_scan_id  ON arniko_findings(scan_id);
CREATE INDEX arniko_findings_severity ON arniko_findings(severity);
CREATE INDEX arniko_findings_resolved ON arniko_findings(resolved);
CREATE INDEX arniko_findings_tool     ON arniko_findings(tool);

-- Shield events (from SecurityShield middleware)
CREATE TABLE IF NOT EXISTS arniko_shield_events (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     TEXT NOT NULL,
  event_type  TEXT NOT NULL,  -- blocked_request|pii_redacted|budget_exceeded|anomaly_detected
  severity    TEXT NOT NULL,
  input_hash  TEXT NOT NULL,  -- SHA-256 of input (never store raw)
  reason      TEXT NOT NULL,
  metadata    JSONB DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX arniko_shield_user_id   ON arniko_shield_events(user_id);
CREATE INDEX arniko_shield_type      ON arniko_shield_events(event_type);
CREATE INDEX arniko_shield_created   ON arniko_shield_events(created_at DESC);

-- Risk scores (updated on scan completion)
CREATE TABLE IF NOT EXISTS arniko_risk_scores (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           TEXT,
  app_id            TEXT,
  overall_score     INTEGER NOT NULL DEFAULT 0,  -- 0-100
  injection_risk    INTEGER NOT NULL DEFAULT 0,
  pii_risk          INTEGER NOT NULL DEFAULT 0,
  cost_risk         INTEGER NOT NULL DEFAULT 0,
  secret_risk       INTEGER NOT NULL DEFAULT 0,
  trend             TEXT DEFAULT 'stable',       -- improving|stable|worsening
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, app_id)
);

CREATE INDEX arniko_risk_user ON arniko_risk_scores(user_id);

-- Garak probe results (LLM-specific vulnerability tracking)
CREATE TABLE IF NOT EXISTS arniko_garak_results (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id    UUID NOT NULL REFERENCES arniko_findings(id) ON DELETE CASCADE,
  probe_type    TEXT NOT NULL,
  success_rate  FLOAT NOT NULL DEFAULT 0.0,  -- 0-1: how often attack succeeded
  sample_attacks TEXT[],
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Alert configurations per user/app
CREATE TABLE IF NOT EXISTS arniko_alert_configs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      TEXT NOT NULL,
  channel      TEXT NOT NULL,  -- slack|pagerduty|email|webhook
  config       JSONB NOT NULL, -- Channel-specific config (webhook URL, etc.)
  severity_min TEXT DEFAULT 'high',  -- Minimum severity to alert on
  enabled      BOOLEAN DEFAULT true,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, channel)
);

CREATE INDEX arniko_alert_user ON arniko_alert_configs(user_id);
