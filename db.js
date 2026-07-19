// db.js — AgroNet Africa Backend
// Production-grade PostgreSQL connection pool
// Optimized for high-concurrency traffic on Render / Railway / Supabase / Neon

'use strict';

require('dotenv').config();
const { Pool } = require('pg');

// ─────────────────────────────────────────────────────────────────────────────
// Pool Configuration
// Tuned for high-traffic production workloads:
//   - max: 20 concurrent connections (Render free tier allows ~25)
//   - idleTimeoutMillis: release idle connections after 30 s
//   - connectionTimeoutMillis: fail fast (5 s) rather than hanging under load
//   - allowExitOnIdle: lets the process exit cleanly in CLI / test scripts
// ─────────────────────────────────────────────────────────────────────────────
const poolConfig = {
  connectionString: process.env.DATABASE_URL,

  // SSL: required for Render, Railway, Supabase, Neon in production
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false,

  // --- Connection limits ---
  max: parseInt(process.env.DB_POOL_MAX, 10) || 20,          // max open connections
  min: parseInt(process.env.DB_POOL_MIN, 10) || 2,           // keep at least 2 warm

  // --- Timeout settings (milliseconds) ---
  idleTimeoutMillis:    parseInt(process.env.DB_IDLE_TIMEOUT, 10)    || 30_000,   // 30 s
  connectionTimeoutMillis: parseInt(process.env.DB_CONN_TIMEOUT, 10) || 5_000,    // 5 s

  // --- Reliability ---
  allowExitOnIdle: false,   // keep pool alive for long-running server processes
};

if (!process.env.DATABASE_URL) {
  console.warn(
    '[DB] ⚠️  DATABASE_URL is not set. ' +
    'The server will start but all database operations will fail. ' +
    'Create a .env file (see .env.example).'
  );
}

const pool = new Pool(poolConfig);

// ─────────────────────────────────────────────────────────────────────────────
// Startup connection check
// ─────────────────────────────────────────────────────────────────────────────
pool.connect((err, client, release) => {
  if (err) {
    console.error('[DB] ❌ PostgreSQL connection failed:', err.message);
  } else {
    console.log(
      `[DB] ✅ Pool connected (max=${poolConfig.max}, idle=${poolConfig.idleTimeoutMillis}ms)`
    );
    release();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Global pool error handler — prevents uncaught exception from crashing server
// ─────────────────────────────────────────────────────────────────────────────
pool.on('error', (err) => {
  console.error('[DB] Unexpected pool client error:', err.message);
  // Do NOT exit — let the pool recover and acquire a new client
});

// ─────────────────────────────────────────────────────────────────────────────
// Graceful shutdown helper — call this on SIGTERM / SIGINT
// ─────────────────────────────────────────────────────────────────────────────
const shutdown = async () => {
  console.log('[DB] Draining connection pool…');
  await pool.end();
  console.log('[DB] Pool drained. Goodbye.');
};

module.exports = { pool, shutdown };
