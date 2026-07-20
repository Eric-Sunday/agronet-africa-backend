// server.js — AgroNet Africa Backend v2.0
// Production-ready Express server: security hardening, rate limiting,
// compression, full CRUD endpoints, authentication, and graceful shutdown.

'use strict';

require('dotenv').config();

const express      = require('express');
const helmet       = require('helmet');
const compression  = require('compression');
const cors         = require('cors');
const rateLimit    = require('express-rate-limit');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const { pool, shutdown } = require('./db');
const { verifyToken }    = require('./middleware/auth');

// ── Process-level safety nets ─────────────────────────────────────────────────
// Prevent unhandled async rejections from crashing the server process
process.on('unhandledRejection', (reason, promise) => {
  console.error('[PROCESS] Unhandled Promise Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[PROCESS] Uncaught Exception:', err.message);
  // Don't exit — allow Express error handler to manage request-level errors
});

const app = express();

// ── Trust Render's reverse proxy (MUST be first) ─────────────────────────────
// Required for express-rate-limit to correctly read the real client IP
// from the X-Forwarded-For header set by Render's load balancer.
app.set('trust proxy', 1);

// Isolate all secrets strictly within process.env
const PORT       = process.env.PORT       || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'agronet-dev-secret-key-123';

// ═════════════════════════════════════════════════════════════════════════════
// SECURITY MIDDLEWARE
// ═════════════════════════════════════════════════════════════════════════════

// Helmet — sets 14 security-related HTTP response headers
app.use(helmet());

app.use(cors({
  origin: [
    'https://agronet-africa.vercel.app', 
    'http://localhost:5173'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

// ═════════════════════════════════════════════════════════════════════════════
// PERFORMANCE MIDDLEWARE
// ═════════════════════════════════════════════════════════════════════════════

// Compress all JSON/text responses — significant bandwidth savings on mobile
app.use(compression({ level: 6, threshold: 1024 }));

// ═════════════════════════════════════════════════════════════════════════════
// RATE LIMITING — DDoS / Abuse Prevention
// ═════════════════════════════════════════════════════════════════════════════

// Global limiter: 200 requests per 15 minutes per IP
// validate.trustProxy=false suppresses the ERR_ERL_UNEXPECTED_X_FORWARDED_FOR
// warning since we already set 'trust proxy' above.
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
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
  validate: { trustProxy: false },
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
      login:         'POST /api/auth/login',
      profile:       'GET  /api/users/profile',
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
 * Body: { name, email, password, phone?, role?, location? }
 *   role: 'farmer' | 'agent' | 'admin'  (default: 'farmer')
 *
 * Returns 201 with the created user profile and JWT token.
 */
app.post(
  '/api/users',
  strictLimiter,
  asyncHandler(async (req, res) => {
    const { name, email, password, phone, role = 'farmer', location } = req.body;

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
    if (!password || typeof password !== 'string' || password.length < 6) {
      return validationError(res, '"password" is required and must be at least 6 characters.');
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
      [email.toLowerCase().trim()]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'Conflict',
        message: 'A user with this email already exists.',
      });
    }

    // ── Password Hashing ──────────────────────────────────────────────────
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // ── Insert ────────────────────────────────────────────────────────────
    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash, phone, role, location)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, email, phone, role, location, is_verified, created_at`,
      [
        name.trim(),
        email.toLowerCase().trim(),
        passwordHash,
        phone  ? phone.trim()    : null,
        role,
        location ? location.trim() : null,
      ]
    );

    const user = result.rows[0];

    // ── Generate JWT ──────────────────────────────────────────────────────
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.status(201).json({
      success: true,
      message: 'User registered successfully.',
      token,
      user
    });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: POST /api/auth/login — User Login
// ═════════════════════════════════════════════════════════════════════════════
/**
 * Authenticates an AgroNet Africa user.
 *
 * Body: { email, password }
 *
 * Returns 200 with the JWT token and user profile.
 */
app.post(
  '/api/auth/login',
  strictLimiter,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email || typeof email !== 'string') {
      return validationError(res, 'Email is required.');
    }
    if (!password) {
      return validationError(res, 'Password is required.');
    }

    const result = await pool.query(
      `SELECT id, name, email, password_hash, phone, role, location, is_verified, created_at
       FROM users
       WHERE email = $1`,
      [email.toLowerCase().trim()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: 'Unauthorized',
        message: 'Invalid credentials.',
      });
    }

    const userRecord = result.rows[0];

    // ── Verify Password ───────────────────────────────────────────────────
    const isMatch = await bcrypt.compare(password, userRecord.password_hash);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        error: 'Unauthorized',
        message: 'Invalid credentials.',
      });
    }

    // ── Remove password hash from response payload ────────────────────────
    const { password_hash, ...user } = userRecord;

    // ── Generate JWT ──────────────────────────────────────────────────────
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.status(200).json({
      success: true,
      message: 'Login successful.',
      token,
      user
    });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: GET /api/users/profile — Fetch Current Authenticated User Profile
// ═════════════════════════════════════════════════════════════════════════════
/**
 * Fetches the currently logged-in user's profile using their JWT.
 * Powers the custom user dashboard on the frontend.
 *
 * Headers: { Authorization: 'Bearer <token>' }
 */
app.get(
  '/api/users/profile',
  verifyToken,
  asyncHandler(async (req, res) => {
    // req.user is populated by verifyToken middleware
    const { id } = req.user;

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
        message: 'User profile not found.',
      });
    }

    return res.status(200).json({
      success: true,
      user: result.rows[0],
    });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: POST /api/dispatch — Contextual Dispatch / Emergency Triage
// ═════════════════════════════════════════════════════════════════════════════
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

    if (!distress_input || typeof distress_input !== 'string' || !distress_input.trim()) {
      return validationError(
        res,
        '"distress_input" is required. Describe the emergency or situation in plain language.'
      );
    }

    const VALID_SEVERITIES = ['low', 'medium', 'high', 'critical'];
    if (!VALID_SEVERITIES.includes(severity)) {
      return validationError(res, `"severity" must be one of: ${VALID_SEVERITIES.join(', ')}.`);
    }

    const VALID_ESCROW = ['pending', 'held', 'released', 'refunded'];
    if (!VALID_ESCROW.includes(escrow_status)) {
      return validationError(res, `"escrow_status" must be one of: ${VALID_ESCROW.join(', ')}.`);
    }

    if (latitude !== null && (isNaN(latitude) || Math.abs(latitude) > 90)) {
      return validationError(res, '"latitude" must be a number between -90 and 90.');
    }
    if (longitude !== null && (isNaN(longitude) || Math.abs(longitude) > 180)) {
      return validationError(res, '"longitude" must be a number between -180 and 180.');
    }

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

    console.log(`[DISPATCH] 🚨 ${severity.toUpperCase()} | ID: ${record.id} | Team: ${assignedTeam}`);

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
// ROUTE: GET /api/users/:id — Fetch a Single User Profile by ID
// ═════════════════════════════════════════════════════════════════════════════
app.get(
  '/api/users/:id',
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    // Basic UUID format guard before hitting the DB
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!UUID_RE.test(id)) {
      return res.status(400).json({
        success: false,
        error: 'Bad Request',
        message: 'User ID must be a valid UUID.',
      });
    }

    const result = await pool.query(
      `SELECT id, name, email, phone, role, location, is_verified, created_at
       FROM users WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Not Found',
        message: 'User not found.',
      });
    }

    return res.status(200).json({ success: true, data: result.rows[0] });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: GET /api/jobs — Fetch Active Jobs (Paginated)
// ═════════════════════════════════════════════════════════════════════════════
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
      return validationError(res, `"status" must be one of: ${VALID_STATUS.join(', ')}.`);
    }

    const params  = [status, limit, offset];
    let whereClause = 'WHERE j.status = $1';

    if (locationKw) {
      params.push(`%${locationKw.toLowerCase()}%`);
      whereClause += ` AND LOWER(j.location) LIKE $${params.length}`;
    }

    const jobsQuery = `
      SELECT
        j.id, j.title, j.description, j.location, j.status, j.created_at,
        u.id   AS farmer_id,
        u.name AS farmer_name
      FROM jobs j
      LEFT JOIN users u ON u.id = j.farmer_id
      ${whereClause}
      ORDER BY j.created_at DESC
      LIMIT $2 OFFSET $3
    `;

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
        page, limit, total, total_pages: totalPages,
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
// ═════════════════════════════════════════════════════════════════════════════
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  if (err.message && err.message.startsWith('CORS:')) {
    return res.status(403).json({ success: false, error: 'Forbidden', message: err.message });
  }

  if (err.code === '42P01') {
    return res.status(503).json({
      success: false,
      error: 'Database Not Initialized',
      message: 'Required tables are missing. Run init.sql against your database.',
    });
  }

  if (err.code === '23505') {
    return res.status(409).json({
      success: false,
      error: 'Conflict',
      message: 'A record with this data already exists.',
    });
  }

  if (err.code === '23503') {
    return res.status(422).json({
      success: false,
      error: 'Unprocessable Entity',
      message: 'Referenced resource does not exist.',
    });
  }

  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      success: false,
      error: 'Bad Request',
      message: 'Request body contains invalid JSON.',
    });
  }

  if (err.status === 413) {
    return res.status(413).json({
      success: false,
      error: 'Payload Too Large',
      message: 'Request body exceeds the 50 KB limit.',
    });
  }

  console.error('[ERROR]', err.stack || err.message);
  return res.status(500).json({
    success: false,
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong. Please try again later.',
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// START SERVER
// ═════════════════════════════════════════════════════════════════════════════
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('🌿 ══════════════════════════════════════════════════════');
  console.log('   AgroNet Africa Backend v2.0 — Production Server');
  console.log('🌿 ══════════════════════════════════════════════════════');
  console.log(`   🚀  URL:         http://localhost:${PORT}`);
  console.log(`   📦  Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   🗄️   Database:    ${process.env.DATABASE_URL ? '✅ Configured' : '⚠️  DATABASE_URL not set'}`);
  console.log(`   🛡️   Security:    helmet ✅  rate-limit ✅  compression ✅  jwt ✅`);
  console.log('🌿 ══════════════════════════════════════════════════════');
  console.log('');
});

// ═════════════════════════════════════════════════════════════════════════════
// GRACEFUL SHUTDOWN
// ═════════════════════════════════════════════════════════════════════════════
const gracefulShutdown = async (signal) => {
  console.log(`\n[SERVER] ${signal} received. Shutting down gracefully…`);
  server.close(async () => {
    await shutdown(); // drain the DB pool
    console.log('[SERVER] ✅ Shutdown complete.');
    process.exit(0);
  });

  setTimeout(() => {
    console.error('[SERVER] Forced shutdown after 10 s timeout.');
    process.exit(1);
  }, 10_000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

module.exports = app;
