// server.js — AgroNet Africa Backend v2.0
// Production-ready Express server: security hardening, rate limiting,
// compression, full CRUD endpoints, and graceful shutdown.

'use strict';

require('dotenv').config();

const express      = require('express');
const helmet       = require('helmet');
const compression  = require('compression');
const cors         = require('cors');
const rateLimit    = require('express-rate-limit');
const { pool, shutdown } = require('./db');

const app  = express();
const PORT = process.env.PORT || 5000;

// ═════════════════════════════════════════════════════════════════════════════
// SECURITY MIDDLEWARE
// ═════════════════════════════════════════════════════════════════════════════

// Helmet — sets 14 security-related HTTP response headers
app.use(helmet());

// CORS — explicitly allow only the Vercel frontend domain (+ localhost for dev)
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim())
  : ['http://localhost:3000'];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow server-to-server requests (no Origin header) and listed origins
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      callback(new Error(`CORS: origin '${origin}' not allowed`));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// PERFORMANCE MIDDLEWARE
// ═════════════════════════════════════════════════════════════════════════════

// Compress all JSON/text responses — significant bandwidth savings on mobile
app.use(compression({ level: 6, threshold: 1024 }));

// ═════════════════════════════════════════════════════════════════════════════
// RATE LIMITING — DDoS / Abuse Prevention
// ═════════════════════════════════════════════════════════════════════════════

// Global limiter: 200 requests per 15 minutes per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too Many Requests',
    message: 'You have exceeded the request limit. Please wait and try again.',
  },
});

// Strict limiter for write/auth endpoints: 20 requests per 15 minutes per IP
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too Many Requests',
    message: 'Too many registration or dispatch attempts. Please slow down.',
  },
});

app.use(globalLimiter);

// ═════════════════════════════════════════════════════════════════════════════
// BODY PARSING
// ═════════════════════════════════════════════════════════════════════════════
app.use(express.json({ limit: '50kb' }));            // cap payload size
app.use(express.urlencoded({ extended: true, limit: '50kb' }));

// ═════════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═════════════════════════════════════════════════════════════════════════════

/** Email format validator */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Validate email format */
const isValidEmail = (email) => EMAIL_RE.test(email);

/** Wrap async route handlers to forward errors to the global error handler */
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/** Build a structured validation error response */
const validationError = (res, message) =>
  res.status(400).json({ success: false, error: 'Validation Error', message });

/** Build a structured DB-unavailable response */
const dbUnavailable = (res) =>
  res.status(503).json({
    success: false,
    error: 'Database Unavailable',
    message: 'Database tables are not yet initialized. Run init.sql first.',
  });

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: GET / — Health Check
// ═════════════════════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'AgroNet Africa Backend',
    version: '2.0.0',
    message: '🌿 AgroNet Africa API is live and production-ready.',
    timestamp: new Date().toISOString(),
    uptime_seconds: Math.floor(process.uptime()),
    endpoints: {
      health:        'GET  /',
      register:      'POST /api/users',
      user_profile:  'GET  /api/users/:id',
      dispatch:      'POST /api/dispatch',
      jobs:          'GET  /api/jobs?page=1&limit=20&status=active',
    },
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: POST /api/users — User Registration
// ═════════════════════════════════════════════════════════════════════════════
/**
 * Registers a new AgroNet Africa user.
 *
 * Body: { name, email, phone?, role?, location? }
 *   role: 'farmer' | 'agent' | 'admin'  (default: 'farmer')
 *
 * Returns 201 with the created user profile.
 */
app.post(
  '/api/users',
  strictLimiter,
  asyncHandler(async (req, res) => {
    const { name, email, phone, role = 'farmer', location } = req.body;

    // ── Input Validation ──────────────────────────────────────────────────
    if (!name || typeof name !== 'string' || !name.trim()) {
      return validationError(res, '"name" is required and must be a non-empty string.');
    }
    if (!email || typeof email !== 'string') {
      return validationError(res, '"email" is required.');
    }
    if (!isValidEmail(email)) {
      return validationError(res, 'Please provide a valid email address.');
    }

    const VALID_ROLES = ['farmer', 'agent', 'admin'];
    if (!VALID_ROLES.includes(role)) {
      return validationError(
        res,
        `"role" must be one of: ${VALID_ROLES.join(', ')}.`
      );
    }

    // ── Duplicate check ───────────────────────────────────────────────────
    const existing = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase()]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'Conflict',
        message: 'A user with this email already exists.',
      });
    }

    // ── Insert ────────────────────────────────────────────────────────────
    const result = await pool.query(
      `INSERT INTO users (name, email, phone, role, location)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, email, phone, role, location, is_verified, created_at`,
      [
        name.trim(),
        email.toLowerCase().trim(),
        phone  ? phone.trim()    : null,
        role,
        location ? location.trim() : null,
      ]
    );

    return res.status(201).json({
      success: true,
      message: 'User registered successfully.',
      data: result.rows[0],
    });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: GET /api/users/:id — Fetch User Profile (Dashboard)
// ═════════════════════════════════════════════════════════════════════════════
/**
 * Fetches a single user's profile by UUID.
 * Powers the custom user dashboard on the frontend.
 *
 * Params: :id — UUID of the user
 */
app.get(
  '/api/users/:id',
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    // Basic UUID shape check to avoid expensive DB round-trip
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!UUID_RE.test(id)) {
      return validationError(res, 'Invalid user ID format. Must be a valid UUID.');
    }

    const result = await pool.query(
      `SELECT id, name, email, phone, role, location, is_verified, created_at
       FROM users
       WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Not Found',
        message: 'No user found with the provided ID.',
      });
    }

    return res.status(200).json({
      success: true,
      data: result.rows[0],
    });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: POST /api/dispatch — Contextual Dispatch / Emergency Triage
// ═════════════════════════════════════════════════════════════════════════════
/**
 * Accepts a natural language distress string, GPS coordinates, and optional
 * farmer_id for the Core AI Innovation module. Persists to the dispatches table
 * and returns a structured triage ticket.
 *
 * Body: {
 *   farmer_id?,        — UUID of the reporting farmer (optional)
 *   distress_input,    — Free-text natural language distress description (required)
 *   latitude?,         — GPS latitude (e.g. 6.5244)
 *   longitude?,        — GPS longitude (e.g. 3.3792)
 *   ai_classification?,— AI model label (e.g. "pest_outbreak") — set by AI layer
 *   severity?,         — 'low' | 'medium' | 'high' | 'critical' (default: 'medium')
 *   escrow_status?,    — 'pending' | 'held' | 'released' | 'refunded' (default: 'pending')
 * }
 */
app.post(
  '/api/dispatch',
  strictLimiter,
  asyncHandler(async (req, res) => {
    const {
      farmer_id        = null,
      distress_input,
      latitude         = null,
      longitude        = null,
      ai_classification = null,
      severity         = 'medium',
      escrow_status    = 'pending',
    } = req.body;

    // ── Input Validation ──────────────────────────────────────────────────
    if (!distress_input || typeof distress_input !== 'string' || !distress_input.trim()) {
      return validationError(
        res,
        '"distress_input" is required. Describe the emergency or situation in plain language.'
      );
    }

    const VALID_SEVERITIES = ['low', 'medium', 'high', 'critical'];
    if (!VALID_SEVERITIES.includes(severity)) {
      return validationError(
        res,
        `"severity" must be one of: ${VALID_SEVERITIES.join(', ')}.`
      );
    }

    const VALID_ESCROW = ['pending', 'held', 'released', 'refunded'];
    if (!VALID_ESCROW.includes(escrow_status)) {
      return validationError(
        res,
        `"escrow_status" must be one of: ${VALID_ESCROW.join(', ')}.`
      );
    }

    if (latitude !== null && (isNaN(latitude) || Math.abs(latitude) > 90)) {
      return validationError(res, '"latitude" must be a number between -90 and 90.');
    }
    if (longitude !== null && (isNaN(longitude) || Math.abs(longitude) > 180)) {
      return validationError(res, '"longitude" must be a number between -180 and 180.');
    }

    // ── Contextual Dispatch Classification ───────────────────────────────
    const DISPATCH_TEAMS = {
      pest_outbreak: 'Agro-Pest Response Unit',
      flood:         'Water & Drainage Emergency Team',
      drought:       'Climate Resilience Unit',
      livestock:     'Veterinary & Livestock Division',
      fire:          'Rural Fire Service Coordination',
      default:       'General Agricultural Support',
    };

    const RESPONSE_SLA = {
      low:      '48–72 hours',
      medium:   '12–24 hours',
      high:     '2–4 hours',
      critical: '< 1 hour — ESCALATE IMMEDIATELY',
    };

    const classificationKey = ai_classification?.toLowerCase().replace(/\s+/g, '_');
    const assignedTeam      = DISPATCH_TEAMS[classificationKey] || DISPATCH_TEAMS.default;

    // ── Persist to DB ─────────────────────────────────────────────────────
    const result = await pool.query(
      `INSERT INTO dispatches
         (farmer_id, distress_input, latitude, longitude, ai_classification,
          escrow_status, severity, assigned_team)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, farmer_id, distress_input, latitude, longitude,
                 ai_classification, escrow_status, severity, assigned_team,
                 response_status, created_at`,
      [
        farmer_id,
        distress_input.trim(),
        latitude  !== null ? parseFloat(latitude)  : null,
        longitude !== null ? parseFloat(longitude) : null,
        ai_classification || null,
        escrow_status,
        severity,
        assignedTeam,
      ]
    );

    const record = result.rows[0];

    console.log(
      `[DISPATCH] 🚨 ${severity.toUpperCase()} | ID: ${record.id} | Team: ${assignedTeam}`
    );

    return res.status(201).json({
      success: true,
      message: 'Emergency triage dispatch created successfully.',
      data: {
        ...record,
        expected_response_time: RESPONSE_SLA[severity],
      },
    });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: GET /api/jobs — Fetch Active Jobs (Paginated)
// ═════════════════════════════════════════════════════════════════════════════
/**
 * Returns a paginated list of job postings.
 * Supports high-volume infinite scroll without lagging.
 *
 * Query params:
 *   page   {number} — page number, 1-based (default: 1)
 *   limit  {number} — items per page, max 100 (default: 20)
 *   status {string} — 'active' | 'filled' | 'closed' | 'draft' (default: 'active')
 *   location {string} — filter by location keyword (optional)
 */
app.get(
  '/api/jobs',
  asyncHandler(async (req, res) => {
    const rawPage     = parseInt(req.query.page,  10);
    const rawLimit    = parseInt(req.query.limit, 10);
    const status      = req.query.status   || 'active';
    const locationKw  = req.query.location || null;

    const page  = Number.isFinite(rawPage)  && rawPage  > 0 ? rawPage  : 1;
    const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 100) : 20;
    const offset = (page - 1) * limit;

    const VALID_STATUS = ['active', 'filled', 'closed', 'draft'];
    if (!VALID_STATUS.includes(status)) {
      return validationError(
        res,
        `"status" must be one of: ${VALID_STATUS.join(', ')}.`
      );
    }

    // Build dynamic query with optional location filter
    const params  = [status, limit, offset];
    let whereClause = 'WHERE j.status = $1';

    if (locationKw) {
      params.push(`%${locationKw.toLowerCase()}%`);
      whereClause += ` AND LOWER(j.location) LIKE $${params.length}`;
    }

    // Fetch jobs with farmer name via JOIN, ordered newest first
    const jobsQuery = `
      SELECT
        j.id,
        j.title,
        j.description,
        j.location,
        j.status,
        j.created_at,
        u.id   AS farmer_id,
        u.name AS farmer_name
      FROM jobs j
      LEFT JOIN users u ON u.id = j.farmer_id
      ${whereClause}
      ORDER BY j.created_at DESC
      LIMIT $2 OFFSET $3
    `;

    // Total count for pagination metadata (uses same filter, no LIMIT)
    const countParams  = [status];
    let countWhere     = 'WHERE status = $1';
    if (locationKw) {
      countParams.push(`%${locationKw.toLowerCase()}%`);
      countWhere += ` AND LOWER(location) LIKE $${countParams.length}`;
    }
    const countQuery = `SELECT COUNT(*) AS total FROM jobs ${countWhere}`;

    const [jobsResult, countResult] = await Promise.all([
      pool.query(jobsQuery,  params),
      pool.query(countQuery, countParams),
    ]);

    const total      = parseInt(countResult.rows[0].total, 10);
    const totalPages = Math.ceil(total / limit);

    return res.status(200).json({
      success: true,
      data: jobsResult.rows,
      pagination: {
        page,
        limit,
        total,
        total_pages: totalPages,
        has_next:    page < totalPages,
        has_prev:    page > 1,
      },
    });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// 404 HANDLER
// ═════════════════════════════════════════════════════════════════════════════
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not Found',
    message: `Route ${req.method} ${req.originalUrl} does not exist.`,
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// CENTRALIZED ERROR HANDLER
// All errors thrown inside asyncHandler() land here.
// The server NEVER crashes on bad input or unexpected exceptions.
// ═════════════════════════════════════════════════════════════════════════════
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  // CORS errors from our whitelist
  if (err.message && err.message.startsWith('CORS:')) {
    return res.status(403).json({
      success: false,
      error: 'Forbidden',
      message: err.message,
    });
  }

  // PostgreSQL: table not found (schema not yet initialized)
  if (err.code === '42P01') {
    return res.status(503).json({
      success: false,
      error: 'Database Not Initialized',
      message: 'Required tables are missing. Run init.sql against your database.',
    });
  }

  // PostgreSQL: unique constraint violation
  if (err.code === '23505') {
    return res.status(409).json({
      success: false,
      error: 'Conflict',
      message: 'A record with this data already exists.',
    });
  }

  // PostgreSQL: foreign key violation
  if (err.code === '23503') {
    return res.status(422).json({
      success: false,
      error: 'Unprocessable Entity',
      message: 'Referenced resource does not exist.',
    });
  }

  // JSON parse error from express.json()
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      success: false,
      error: 'Bad Request',
      message: 'Request body contains invalid JSON.',
    });
  }

  // Payload too large
  if (err.status === 413) {
    return res.status(413).json({
      success: false,
      error: 'Payload Too Large',
      message: 'Request body exceeds the 50 KB limit.',
    });
  }

  // Default: internal server error (log full stack in development only)
  console.error('[ERROR]', err.stack || err.message);
  return res.status(500).json({
    success: false,
    error: 'Internal Server Error',
    message:
      process.env.NODE_ENV === 'development'
        ? err.message
        : 'Something went wrong. Please try again later.',
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// START SERVER
// ═════════════════════════════════════════════════════════════════════════════
const server = app.listen(PORT, () => {
  console.log('');
  console.log('🌿 ══════════════════════════════════════════════════════');
  console.log('   AgroNet Africa Backend v2.0 — Production Server');
  console.log('🌿 ══════════════════════════════════════════════════════');
  console.log(`   🚀  URL:         http://localhost:${PORT}`);
  console.log(`   📦  Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   🗄️   Database:    ${process.env.DATABASE_URL ? '✅ Configured' : '⚠️  DATABASE_URL not set'}`);
  console.log(`   🛡️   Security:    helmet ✅  rate-limit ✅  compression ✅`);
  console.log(`   🌐  CORS:        ${allowedOrigins.join(', ')}`);
  console.log('🌿 ══════════════════════════════════════════════════════');
  console.log('');
});

// ═════════════════════════════════════════════════════════════════════════════
// GRACEFUL SHUTDOWN — Render / Docker / PM2 send SIGTERM before stopping
// ═════════════════════════════════════════════════════════════════════════════
const gracefulShutdown = async (signal) => {
  console.log(`\n[SERVER] ${signal} received. Shutting down gracefully…`);
  server.close(async () => {
    await shutdown(); // drain the DB pool
    console.log('[SERVER] ✅ Shutdown complete.');
    process.exit(0);
  });

  // Force exit if graceful shutdown takes > 10 s
  setTimeout(() => {
    console.error('[SERVER] Forced shutdown after 10 s timeout.');
    process.exit(1);
  }, 10_000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

module.exports = app;
