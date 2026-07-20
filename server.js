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
const { verifyToken, requireRole } = require('./middleware/auth');
const agrilencerRouter = require('./routes/agrilencer');

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
      health:          'GET  /',
      register:        'POST /api/users',
      login:           'POST /api/auth/login',
      profile:         'GET  /api/users/profile',
      dispatch:        'POST /api/dispatch',
      jobs:            'GET  /api/jobs?page=1&limit=20&status=active',
      experts:         'GET  /api/agrilencer/experts',
      expertDetail:    'GET  /api/agrilencer/experts/:id',
      specialties:     'GET  /api/agrilencer/experts/specialties',
      bookings:        'POST /api/agrilencer/bookings',
      bookingStatus:   'PATCH /api/agrilencer/bookings/:id/status',
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
    const {
      // Shared
      email, password, role,
      // Job Seeker fields
      name, location, specialty, skills,
      // Employer fields
      company_name, company_location, tax_id, industry, website,
    } = req.body;

    // ── Shared validation ─────────────────────────────────────────────────
    if (!email || typeof email !== 'string') {
      return validationError(res, '"email" is required.');
    }
    if (!isValidEmail(email)) {
      return validationError(res, 'Please provide a valid email address.');
    }
    if (!password || typeof password !== 'string' || password.length < 6) {
      return validationError(res, '"password" is required and must be at least 6 characters.');
    }

    const VALID_ROLES = ['job_seeker', 'employer'];
    if (!role || !VALID_ROLES.includes(role)) {
      return validationError(res, `"role" must be one of: ${VALID_ROLES.join(', ')}.`);
    }

    // ── Role-specific validation ──────────────────────────────────────────
    if (role === 'job_seeker') {
      if (!name || typeof name !== 'string' || !name.trim()) {
        return validationError(res, '"name" (full name) is required for job seekers.');
      }
      if (!location || !location.trim()) {
        return validationError(res, '"location" is required for job seekers.');
      }
      if (!specialty || !specialty.trim()) {
        return validationError(res, '"specialty" (primary agricultural specialty) is required for job seekers.');
      }
      if (!Array.isArray(skills) || skills.length === 0) {
        return validationError(res, '"skills" must be a non-empty array of skill tags.');
      }
    }

    if (role === 'employer') {
      if (!company_name || typeof company_name !== 'string' || !company_name.trim()) {
        return validationError(res, '"company_name" is required for employers.');
      }
      if (!company_location || !company_location.trim()) {
        return validationError(res, '"company_location" is required for employers.');
      }
      if (!industry || !industry.trim()) {
        return validationError(res, '"industry" (industry sector) is required for employers.');
      }
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

    // ── Atomic insert: users row + role-specific profile row ──────────────
    // Using a DB transaction so a partial failure never leaves an orphaned user.
    const client = await pool.connect();
    let user;
    try {
      await client.query('BEGIN');

      // 1. Insert base user
      const userResult = await client.query(
        `INSERT INTO users (email, password_hash, role)
         VALUES ($1, $2, $3)
         RETURNING id, email, role, is_verified, created_at`,
        [email.toLowerCase().trim(), passwordHash, role]
      );
      user = userResult.rows[0];

      // 2. Insert role-specific profile
      if (role === 'job_seeker') {
        await client.query(
          `INSERT INTO job_seeker_profiles (user_id, full_name, location, specialty, skills)
           VALUES ($1, $2, $3, $4, $5)`,
          [
            user.id,
            name.trim(),
            location.trim(),
            specialty.trim(),
            skills.map(s => String(s).trim()).filter(Boolean),
          ]
        );
        // Attach profile fields to the returned user object
        user.name     = name.trim();
        user.location = location.trim();
        user.specialty = specialty.trim();
        user.skills   = skills;
      } else if (role === 'employer') {
        await client.query(
          `INSERT INTO employer_profiles (user_id, company_name, company_location, tax_id, industry, website)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [
            user.id,
            company_name.trim(),
            company_location.trim(),
            tax_id ? tax_id.trim() : null,
            industry.trim(),
            website ? website.trim() : null,
          ]
        );
        // Attach profile fields to the returned user object
        user.company_name     = company_name.trim();
        user.company_location = company_location.trim();
        user.industry         = industry.trim();
      }

      await client.query('COMMIT');
    } catch (txErr) {
      await client.query('ROLLBACK');
      throw txErr;  // re-throw for the global error handler
    } finally {
      client.release();
    }

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
      user,
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
// ROUTE: GET /api/users/profile — Authenticated Profile (with extended data)
// ═════════════════════════════════════════════════════════════════════════════
app.get(
  '/api/users/profile',
  verifyToken,
  asyncHandler(async (req, res) => {
    const { id, role } = req.user;

    // Fetch base user row
    const userResult = await pool.query(
      'SELECT id, email, role, is_verified, created_at FROM users WHERE id = $1',
      [id]
    );
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Not Found', message: 'User not found.' });
    }
    const user = userResult.rows[0];

    // Fetch role-specific extended profile
    let profile = {};
    if (role === 'job_seeker') {
      const r = await pool.query(
        'SELECT full_name, location, specialty, skills, bio, phone FROM job_seeker_profiles WHERE user_id = $1',
        [id]
      );
      profile = r.rows[0] || {};
    } else if (role === 'employer') {
      const r = await pool.query(
        'SELECT company_name, company_location, tax_id, industry, website, phone FROM employer_profiles WHERE user_id = $1',
        [id]
      );
      profile = r.rows[0] || {};
    }

    return res.status(200).json({
      success: true,
      user: { ...user, ...profile },
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
// ROUTE: GET /api/jobs — Fetch Active Jobs (Paginated, public)
// ═════════════════════════════════════════════════════════════════════════════
app.get(
  '/api/jobs',
  asyncHandler(async (req, res) => {
    const rawPage    = parseInt(req.query.page,  10);
    const rawLimit   = parseInt(req.query.limit, 10);
    const status     = req.query.status   || 'active';
    const locationKw = req.query.location || null;

    const page   = Number.isFinite(rawPage)  && rawPage  > 0 ? rawPage  : 1;
    const limit  = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 100) : 20;
    const offset = (page - 1) * limit;

    const VALID_STATUS = ['active', 'filled', 'closed', 'draft'];
    if (!VALID_STATUS.includes(status)) {
      return validationError(res, `"status" must be one of: ${VALID_STATUS.join(', ')}.`);
    }

    const params = [status, limit, offset];
    let whereClause = 'WHERE j.status = $1';
    if (locationKw) {
      params.push(`%${locationKw.toLowerCase()}%`);
      whereClause += ` AND LOWER(j.location) LIKE $${params.length}`;
    }

    // jobs.employer_id + employer_profiles for company_name
    const jobsQuery = `
      SELECT
        j.id, j.title, j.description, j.location, j.industry, j.salary_range,
        j.status, j.created_at,
        j.employer_id,
        ep.company_name AS employer_name
      FROM jobs j
      LEFT JOIN employer_profiles ep ON ep.user_id = j.employer_id
      ${whereClause}
      ORDER BY j.created_at DESC
      LIMIT $2 OFFSET $3
    `;

    const countParams = [status];
    let countWhere = 'WHERE status = $1';
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
      pagination: { page, limit, total, total_pages: totalPages,
        has_next: page < totalPages, has_prev: page > 1 },
    });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: POST /api/jobs — Create Job (employer only)
// ═════════════════════════════════════════════════════════════════════════════
app.post(
  '/api/jobs',
  strictLimiter,
  verifyToken,
  requireRole(['employer']),
  asyncHandler(async (req, res) => {
    const { title, description, location, industry, salary_range } = req.body;
    if (!title?.trim())       return validationError(res, '"title" is required.');
    if (!description?.trim()) return validationError(res, '"description" is required.');
    if (!location?.trim())    return validationError(res, '"location" is required.');

    const result = await pool.query(
      `INSERT INTO jobs (employer_id, title, description, location, industry, salary_range)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, employer_id, title, description, location, industry, salary_range, status, created_at`,
      [req.user.id, title.trim(), description.trim(), location.trim(),
       industry?.trim() || null, salary_range?.trim() || null]
    );
    return res.status(201).json({ success: true, data: result.rows[0] });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: PUT /api/jobs/:id — Update Job (employer only, must own the listing)
// ═════════════════════════════════════════════════════════════════════════════
app.put(
  '/api/jobs/:id',
  verifyToken,
  requireRole(['employer']),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { title, description, location, industry, salary_range, status } = req.body;

    // Ownership check
    const job = await pool.query('SELECT employer_id FROM jobs WHERE id = $1', [id]);
    if (job.rows.length === 0) return res.status(404).json({ success: false, message: 'Job not found.' });
    if (job.rows[0].employer_id !== req.user.id) {
      return res.status(403).json({ success: false, error: 'Forbidden',
        message: 'Access denied. Only registered employers can manage job listings.' });
    }

    const result = await pool.query(
      `UPDATE jobs SET
         title        = COALESCE($1, title),
         description  = COALESCE($2, description),
         location     = COALESCE($3, location),
         industry     = COALESCE($4, industry),
         salary_range = COALESCE($5, salary_range),
         status       = COALESCE($6, status)
       WHERE id = $7
       RETURNING id, employer_id, title, description, location, industry, salary_range, status, created_at`,
      [title || null, description || null, location || null,
       industry || null, salary_range || null, status || null, id]
    );
    return res.status(200).json({ success: true, data: result.rows[0] });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: DELETE /api/jobs/:id — Delete Job (employer only, must own it)
// ═════════════════════════════════════════════════════════════════════════════
app.delete(
  '/api/jobs/:id',
  verifyToken,
  requireRole(['employer']),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const job = await pool.query('SELECT employer_id FROM jobs WHERE id = $1', [id]);
    if (job.rows.length === 0) return res.status(404).json({ success: false, message: 'Job not found.' });
    if (job.rows[0].employer_id !== req.user.id) {
      return res.status(403).json({ success: false, error: 'Forbidden',
        message: 'Access denied. Only registered employers can manage job listings.' });
    }
    await pool.query('DELETE FROM jobs WHERE id = $1', [id]);
    return res.status(200).json({ success: true, message: 'Job deleted successfully.' });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: POST /api/jobs/:id/apply — Submit Application (job_seeker only)
// ═════════════════════════════════════════════════════════════════════════════
app.post(
  '/api/jobs/:id/apply',
  strictLimiter,
  verifyToken,
  requireRole(['job_seeker']),
  asyncHandler(async (req, res) => {
    const jobId = req.params.id;
    const applicantId = req.user.id;
    const { cover_note } = req.body;

    // Verify job exists
    const job = await pool.query('SELECT id FROM jobs WHERE id = $1 AND status = $2', [jobId, 'active']);
    if (job.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Job not found or no longer active.' });
    }

    const result = await pool.query(
      `INSERT INTO applications (job_id, applicant_id, cover_note)
       VALUES ($1, $2, $3)
       RETURNING id, job_id, applicant_id, cover_note, status, created_at`,
      [jobId, applicantId, cover_note?.trim() || null]
    );
    return res.status(201).json({
      success: true,
      message: 'Application submitted successfully.',
      data: result.rows[0],
    });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// ROUTE: GET /api/jobs/:id/applications — View Applications (employer only, own jobs)
// ═════════════════════════════════════════════════════════════════════════════
app.get(
  '/api/jobs/:id/applications',
  verifyToken,
  requireRole(['employer']),
  asyncHandler(async (req, res) => {
    const jobId = req.params.id;
    const job = await pool.query('SELECT employer_id FROM jobs WHERE id = $1', [jobId]);
    if (job.rows.length === 0) return res.status(404).json({ success: false, message: 'Job not found.' });
    if (job.rows[0].employer_id !== req.user.id) {
      return res.status(403).json({ success: false, error: 'Forbidden',
        message: 'Access denied. Only registered employers can manage job listings.' });
    }
    const apps = await pool.query(
      `SELECT a.id, a.cover_note, a.status, a.created_at,
              p.full_name, p.specialty, p.location AS applicant_location
       FROM applications a
       JOIN job_seeker_profiles p ON p.user_id = a.applicant_id
       WHERE a.job_id = $1
       ORDER BY a.created_at DESC`,
      [jobId]
    );
    return res.status(200).json({ success: true, data: apps.rows });
  })
);

// ═════════════════════════════════════════════════════════════════════════════
// AGRILENCER ROUTER — /api/agrilencer/*
// ═════════════════════════════════════════════════════════════════════════════
app.use('/api/agrilencer', agrilencerRouter);

// ── Legacy aliases — keep old /api/experts/* URLs working for deployed frontend
app.get('/api/experts',             (req, res) => res.redirect(307, `/api/agrilencer/experts?${new URLSearchParams(req.query).toString()}`));
app.get('/api/experts/featured',    (req, res) => res.redirect(307, `/api/agrilencer/experts/featured?${new URLSearchParams(req.query).toString()}`));
app.get('/api/experts/specialties', (req, res) => res.redirect(307, '/api/agrilencer/experts/specialties'));
app.get('/api/experts/:id',         (req, res) => res.redirect(307, `/api/agrilencer/experts/${req.params.id}`));

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
