-- =============================================================================
-- AgroNet Africa — Database Schema Initialization
-- Run this script against your PostgreSQL database to set up all tables.
-- Compatible with: PostgreSQL 14+, Supabase, Neon, Railway, Render PostgreSQL
-- =============================================================================

-- Enable pgcrypto for UUID generation (if available on your host)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- TABLE: users
-- Stores all registered platform users (farmers, agents, admins)
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
  id            UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  name          VARCHAR(150)  NOT NULL,
  email         VARCHAR(255)  NOT NULL UNIQUE,
  phone         VARCHAR(30),
  role          VARCHAR(20)   NOT NULL DEFAULT 'farmer'
                              CHECK (role IN ('farmer', 'agent', 'admin')),
  location      TEXT,
  is_verified   BOOLEAN       NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- Index for fast email lookups (login, duplicate checks)
CREATE INDEX IF NOT EXISTS idx_users_email     ON users (email);
-- Index for role-based filtering (admin dashboards, agent queries)
CREATE INDEX IF NOT EXISTS idx_users_role      ON users (role);
-- Index for location-based queries (regional dispatch, analytics)
CREATE INDEX IF NOT EXISTS idx_users_location  ON users (location);

-- =============================================================================
-- TABLE: jobs
-- Long-term agricultural roles posted by farmers or agents
-- =============================================================================
CREATE TABLE IF NOT EXISTS jobs (
  id            UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  farmer_id     UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title         VARCHAR(200)  NOT NULL,
  description   TEXT          NOT NULL,
  location      TEXT          NOT NULL,
  status        VARCHAR(20)   NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active', 'filled', 'closed', 'draft')),
  created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- Index for fetching jobs by farmer (user dashboard)
CREATE INDEX IF NOT EXISTS idx_jobs_farmer_id  ON jobs (farmer_id);
-- Index for filtering active jobs (public feed with pagination)
CREATE INDEX IF NOT EXISTS idx_jobs_status     ON jobs (status);
-- Composite index for paginated active-jobs feed (status + created_at DESC)
CREATE INDEX IF NOT EXISTS idx_jobs_active_feed ON jobs (status, created_at DESC);

-- =============================================================================
-- TABLE: dispatches
-- Stores emergency triage records for the Core AI Innovation / Contextual Dispatch module.
-- Natural language distress strings, GPS coordinates, AI classification, escrow status.
-- =============================================================================
CREATE TABLE IF NOT EXISTS dispatches (
  id                UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  farmer_id         UUID          REFERENCES users(id) ON DELETE SET NULL,
  distress_input    TEXT          NOT NULL,
  latitude          NUMERIC(9, 6),
  longitude         NUMERIC(9, 6),
  ai_classification VARCHAR(100),
  escrow_status     VARCHAR(30)   NOT NULL DEFAULT 'pending'
                                  CHECK (escrow_status IN ('pending', 'held', 'released', 'refunded')),
  severity          VARCHAR(20)   DEFAULT 'medium'
                                  CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  assigned_team     VARCHAR(150),
  response_status   VARCHAR(30)   NOT NULL DEFAULT 'open'
                                  CHECK (response_status IN ('open', 'in_progress', 'resolved', 'closed')),
  created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- Index for per-farmer dispatch history
CREATE INDEX IF NOT EXISTS idx_dispatches_farmer_id       ON dispatches (farmer_id);
-- Index for filtering by AI classification (analytics, team routing)
CREATE INDEX IF NOT EXISTS idx_dispatches_classification  ON dispatches (ai_classification);
-- Index for open/in-progress response queue
CREATE INDEX IF NOT EXISTS idx_dispatches_response_status ON dispatches (response_status);
-- Index for escrow management queries
CREATE INDEX IF NOT EXISTS idx_dispatches_escrow_status   ON dispatches (escrow_status);

-- =============================================================================
-- END OF SCHEMA
-- =============================================================================
