-- =============================================================================
-- AgroNet Africa — Database Schema v3.0  (RBAC Edition)
-- Run this script against your PostgreSQL database to migrate/initialize.
-- Compatible with: PostgreSQL 14+, Supabase, Neon, Railway, Render PostgreSQL
-- =============================================================================

-- Enable pgcrypto for UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- TABLE: users
-- Stores all registered platform users.
-- Role is immutable once set (enforced by the CHECK + application layer).
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
  id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  email           VARCHAR(255)  NOT NULL UNIQUE,
  password_hash   VARCHAR(255)  NOT NULL,
  role            VARCHAR(20)   NOT NULL
                                CHECK (role IN ('job_seeker', 'employer')),
  is_verified     BOOLEAN       NOT NULL DEFAULT FALSE,
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- TABLE: job_seeker_profiles
-- Extended profile for users with role = 'job_seeker'
-- =============================================================================
CREATE TABLE IF NOT EXISTS job_seeker_profiles (
  user_id         UUID          PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  full_name       VARCHAR(150)  NOT NULL,
  location        TEXT,
  specialty       VARCHAR(150),   -- e.g. "Crop Science", "Agronomy"
  skills          TEXT[],         -- array of skill tags
  bio             TEXT,
  phone           VARCHAR(30),
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- TABLE: employer_profiles
-- Extended profile for users with role = 'employer'
-- =============================================================================
CREATE TABLE IF NOT EXISTS employer_profiles (
  user_id         UUID          PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  company_name    VARCHAR(200)  NOT NULL,
  tax_id          VARCHAR(100),   -- optional registration/tax ID
  company_location TEXT,
  industry        VARCHAR(100),   -- e.g. "Crop Production", "Aquaculture"
  website         VARCHAR(300),
  phone           VARCHAR(30),
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- TABLE: jobs
-- Agricultural roles posted exclusively by employers
-- =============================================================================
CREATE TABLE IF NOT EXISTS jobs (
  id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  employer_id     UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title           VARCHAR(200)  NOT NULL,
  description     TEXT          NOT NULL,
  location        TEXT          NOT NULL,
  industry        VARCHAR(100),
  salary_range    VARCHAR(100),
  status          VARCHAR(20)   NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active', 'filled', 'closed', 'draft')),
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- TABLE: applications
-- Job applications submitted exclusively by job_seekers
-- =============================================================================
CREATE TABLE IF NOT EXISTS applications (
  id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id          UUID          NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  applicant_id    UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cover_note      TEXT,
  status          VARCHAR(20)   NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'reviewed', 'shortlisted', 'rejected', 'hired')),
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  UNIQUE (job_id, applicant_id)  -- prevent duplicate applications
);

-- =============================================================================
-- TABLE: dispatches
-- Emergency triage records for the Contextual Dispatch AI module
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

-- =============================================================================
-- INDEXES
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_users_email            ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_role             ON users (role);
CREATE INDEX IF NOT EXISTS idx_jobs_employer_id       ON jobs (employer_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status            ON jobs (status);
CREATE INDEX IF NOT EXISTS idx_jobs_active_feed       ON jobs (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_applications_job_id    ON applications (job_id);
CREATE INDEX IF NOT EXISTS idx_applications_applicant ON applications (applicant_id);
CREATE INDEX IF NOT EXISTS idx_dispatches_farmer_id   ON dispatches (farmer_id);

-- =============================================================================
-- TABLE: expert_profiles
-- On-demand agricultural expert marketplace — Agrilencer feature
-- Each row corresponds to a user who has registered as an expert.
-- =============================================================================
CREATE TABLE IF NOT EXISTS expert_profiles (
  id                  UUID          PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  hourly_rate         NUMERIC(10,2) NOT NULL DEFAULT 0.00,
  currency            VARCHAR(10)   NOT NULL DEFAULT 'NGN',
  specialty           VARCHAR(100)  NOT NULL,  -- e.g. 'Agronomist', 'Pathologist'
  years_experience    INT           NOT NULL DEFAULT 0,
  location_state      VARCHAR(100)  NOT NULL,
  geo_latitude        NUMERIC(10,8),
  geo_longitude       NUMERIC(11,8),
  verification_status VARCHAR(20)   NOT NULL DEFAULT 'pending'
                                    CHECK (verification_status IN ('pending', 'verified', 'rejected')),
  rating              NUMERIC(3,2)  NOT NULL DEFAULT 5.00
                                    CHECK (rating >= 0.00 AND rating <= 5.00),
  bio                 TEXT,
  created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- TABLE: consultation_bookings
-- Escrow-backed consultation records between a client and an expert.
-- =============================================================================
CREATE TABLE IF NOT EXISTS consultation_bookings (
  id               UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id        UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expert_id        UUID          NOT NULL REFERENCES expert_profiles(id) ON DELETE CASCADE,
  farm_issue_title VARCHAR(255)  NOT NULL,
  description      TEXT          NOT NULL,
  urgency_level    VARCHAR(30)   NOT NULL DEFAULT 'medium'
                                 CHECK (urgency_level IN ('low', 'medium', 'critical_crisis')),
  escrow_amount    NUMERIC(10,2) NOT NULL,
  escrow_status    VARCHAR(30)   NOT NULL DEFAULT 'held_in_escrow'
                                 CHECK (escrow_status IN ('pending_payment', 'held_in_escrow', 'disbursed', 'refunded')),
  booking_status   VARCHAR(30)   NOT NULL DEFAULT 'requested'
                                 CHECK (booking_status IN ('requested', 'accepted', 'completed', 'cancelled')),
  created_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- INDEXES — Agrilencer
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_expert_specialty         ON expert_profiles (specialty);
CREATE INDEX IF NOT EXISTS idx_expert_location          ON expert_profiles (location_state);
CREATE INDEX IF NOT EXISTS idx_expert_verification      ON expert_profiles (verification_status);
CREATE INDEX IF NOT EXISTS idx_expert_rating            ON expert_profiles (rating DESC);
CREATE INDEX IF NOT EXISTS idx_bookings_client          ON consultation_bookings (client_id);
CREATE INDEX IF NOT EXISTS idx_bookings_expert          ON consultation_bookings (expert_id);
CREATE INDEX IF NOT EXISTS idx_bookings_status          ON consultation_bookings (booking_status);

-- =============================================================================
-- END OF SCHEMA v4.0
-- =============================================================================
