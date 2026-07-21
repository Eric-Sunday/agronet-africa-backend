// routes/agrilencer.js — AgroNet Africa Backend
// ─────────────────────────────────────────────────────────────────────────────
// Agrilencer On-Demand Experts marketplace routes.
// All expert-listing endpoints are public. Booking endpoints require JWT.
//
// Mount in server.js:
//   const agrilencerRouter = require('./routes/agrilencer');
//   app.use('/api/agrilencer', agrilencerRouter);
// ─────────────────────────────────────────────────────────────────────────────

'use strict';

const express = require('express');
const { pool } = require('../db');
const { verifyToken } = require('../middleware/auth');

const router = express.Router();

// ── Utility helpers ───────────────────────────────────────────────────────────

/** Wrap async route handlers to forward errors to the global error handler */
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/** Structured 400 validation error */
const validationError = (res, message) =>
  res.status(400).json({ success: false, error: 'Validation Error', message });

/** Structured 403 forbidden error */
const forbiddenError = (res, message) =>
  res.status(403).json({ success: false, error: 'Forbidden', message });

/** Structured 404 not-found error */
const notFoundError = (res, message) =>
  res.status(404).json({ success: false, error: 'Not Found', message });

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/agrilencer/experts/specialties
// Public — returns the distinct list of specialties for filter dropdowns.
// SAFE: returns [] on any DB error to prevent frontend network error banners.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/experts/specialties', async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT specialty
       FROM expert_profiles
       WHERE verification_status = 'verified'
       ORDER BY specialty ASC`
    );
    return res.status(200).json({
      success: true,
      data: result.rows.map(r => r.specialty),
    });
  } catch (err) {
    console.error('[AGRILENCER] GET /experts/specialties DB error:', err.message);
    // Return graceful empty response so frontend doesn't show connection error
    return res.status(200).json({ success: true, data: [] });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/agrilencer/experts/featured
// Public — top-rated verified experts (limit param, default 4).
// SAFE: returns [] on any DB error to prevent frontend network error banners.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/experts/featured', async (req, res) => {
  try {
    const rawLimit = parseInt(req.query.limit, 10);
    const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 20) : 4;

    const result = await pool.query(
      `SELECT
         ep.id, ep.hourly_rate, ep.currency, ep.specialty,
         ep.years_experience, ep.location_state, ep.rating, ep.bio,
         ep.verification_status,
         js.full_name, js.phone
       FROM expert_profiles ep
       JOIN job_seeker_profiles js ON js.user_id = ep.id
       WHERE ep.verification_status = 'verified'
       ORDER BY ep.rating DESC, ep.years_experience DESC
       LIMIT $1`,
      [limit]
    );

    return res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    console.error('[AGRILENCER] GET /experts/featured DB error:', err.message);
    return res.status(200).json({ success: true, data: [] });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/agrilencer/experts
// Public — list verified experts with optional filters.
// Query params: ?specialty=, ?state=, ?search=, ?page=, ?limit=
// SAFE: returns empty paginated response on any DB error.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/experts', async (req, res) => {
  try {
    const rawPage  = parseInt(req.query.page,  10);
    const rawLimit = parseInt(req.query.limit, 10);
    const page     = Number.isFinite(rawPage)  && rawPage  > 0 ? rawPage  : 1;
    const limit    = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 100) : 20;
    const offset   = (page - 1) * limit;

    const specialty = req.query.specialty || null;
    const state     = req.query.state     || null;
    const search    = req.query.search    || null;

    // Build dynamic WHERE clauses
    const conditions = ["ep.verification_status = 'verified'"];
    const filterParams = [];  // shared filter params (no LIMIT/OFFSET)

    if (specialty) {
      filterParams.push(specialty);
      conditions.push(`LOWER(ep.specialty) = LOWER($${filterParams.length})`);
    }
    if (state) {
      filterParams.push(`%${state.toLowerCase()}%`);
      conditions.push(`LOWER(ep.location_state) LIKE $${filterParams.length}`);
    }
    if (search) {
      filterParams.push(`%${search.toLowerCase()}%`);
      conditions.push(
        `(LOWER(ep.specialty) LIKE $${filterParams.length} OR LOWER(js.full_name) LIKE $${filterParams.length})`
      );
    }

    const whereSQL = 'WHERE ' + conditions.join(' AND ');

    // pageParams adds LIMIT + OFFSET at the end
    const pageParams = [...filterParams, limit, offset];
    const limitIdx   = pageParams.length - 1;  // $N for LIMIT
    const offsetIdx  = pageParams.length;       // $N+1 for OFFSET

    const expertSQL = `
      SELECT
        ep.id, ep.hourly_rate, ep.currency, ep.specialty,
        ep.years_experience, ep.location_state,
        ep.geo_latitude, ep.geo_longitude,
        ep.rating, ep.bio, ep.verification_status,
        js.full_name, js.phone
      FROM expert_profiles ep
      JOIN job_seeker_profiles js ON js.user_id = ep.id
      ${whereSQL}
      ORDER BY ep.rating DESC, ep.created_at DESC
      LIMIT $${limitIdx} OFFSET $${offsetIdx}
    `;

    // Count query — same WHERE, no LIMIT/OFFSET, uses filterParams only
    const countSQL = `
      SELECT COUNT(*) AS total
      FROM expert_profiles ep
      JOIN job_seeker_profiles js ON js.user_id = ep.id
      ${whereSQL}
    `;

    const [expertsResult, countResult] = await Promise.all([
      pool.query(expertSQL, pageParams),
      pool.query(countSQL,  filterParams),
    ]);

    const total      = parseInt(countResult.rows[0]?.total ?? 0, 10);
    const totalPages = Math.ceil(total / limit) || 1;

    return res.status(200).json({
      success: true,
      data:        expertsResult.rows,
      pagination:  { page, limit, total, total_pages: totalPages,
                     has_next: page < totalPages, has_prev: page > 1 },
    });
  } catch (err) {
    console.error('[AGRILENCER] GET /experts DB error:', err.message);
    // Return graceful empty paginated response — prevents frontend "Could not
    // connect to backend" error banner when the table is empty or DB is cold.
    return res.status(200).json({
      success: true,
      data: [],
      pagination: { page: 1, limit: 20, total: 0, total_pages: 1,
                    has_next: false, has_prev: false },
    });
  }
});


// ─────────────────────────────────────────────────────────────────────────────
// GET /api/agrilencer/experts/:id
// Public — detailed expert profile joined with user metadata.
// SAFE: returns 404 on missing expert; 500 on unexpected DB errors (intentional).
// ─────────────────────────────────────────────────────────────────────────────
router.get(
  '/experts/:id',
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!UUID_RE.test(id)) {
      return validationError(res, 'Expert ID must be a valid UUID.');
    }

    const result = await pool.query(
      `SELECT
         ep.id, ep.hourly_rate, ep.currency, ep.specialty,
         ep.years_experience, ep.location_state,
         ep.geo_latitude, ep.geo_longitude,
         ep.verification_status, ep.rating, ep.bio, ep.created_at,
         js.full_name, js.phone,
         u.email, u.created_at AS member_since
       FROM expert_profiles ep
       JOIN job_seeker_profiles js ON js.user_id = ep.id
       JOIN users u ON u.id = ep.id
       WHERE ep.id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return notFoundError(res, 'Expert profile not found.');
    }

    return res.status(200).json({ success: true, data: result.rows[0] });
  })
);

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/agrilencer/bookings
// Protected — any authenticated user can book an expert.
// Body: { expert_id, farm_issue_title, description, urgency_level, escrow_amount }
// ─────────────────────────────────────────────────────────────────────────────
router.post(
  '/bookings',
  verifyToken,
  asyncHandler(async (req, res) => {
    const {
      expert_id,
      farm_issue_title,
      description,
      urgency_level = 'medium',
      escrow_amount,
    } = req.body;

    // ── Validation ────────────────────────────────────────────────────────
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!expert_id || !UUID_RE.test(expert_id)) {
      return validationError(res, '"expert_id" must be a valid UUID.');
    }
    if (!farm_issue_title?.trim()) {
      return validationError(res, '"farm_issue_title" is required.');
    }
    if (!description?.trim()) {
      return validationError(res, '"description" is required.');
    }
    const VALID_URGENCY = ['low', 'medium', 'critical_crisis'];
    if (!VALID_URGENCY.includes(urgency_level)) {
      return validationError(res, `"urgency_level" must be one of: ${VALID_URGENCY.join(', ')}.`);
    }
    const amount = parseFloat(escrow_amount);
    if (isNaN(amount) || amount <= 0) {
      return validationError(res, '"escrow_amount" must be a positive number.');
    }

    // ── Prevent self-booking ──────────────────────────────────────────────
    if (req.user.id === expert_id) {
      return forbiddenError(res, 'You cannot book a consultation with yourself.');
    }

    // ── Verify expert exists and is verified ──────────────────────────────
    const expertCheck = await pool.query(
      `SELECT id FROM expert_profiles WHERE id = $1 AND verification_status = 'verified'`,
      [expert_id]
    );
    if (expertCheck.rows.length === 0) {
      return notFoundError(res, 'Expert not found or is not yet verified.');
    }

    // ── Insert booking ────────────────────────────────────────────────────
    const result = await pool.query(
      `INSERT INTO consultation_bookings
         (client_id, expert_id, farm_issue_title, description, urgency_level, escrow_amount)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, client_id, expert_id, farm_issue_title, description,
                 urgency_level, escrow_amount, escrow_status, booking_status,
                 created_at, updated_at`,
      [
        req.user.id,
        expert_id,
        farm_issue_title.trim(),
        description.trim(),
        urgency_level,
        amount,
      ]
    );

    return res.status(201).json({
      success: true,
      message: 'Consultation booking created. Escrow held pending expert acceptance.',
      data: result.rows[0],
    });
  })
);

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/agrilencer/bookings
// Protected — returns the caller's own bookings (as client or expert).
// ─────────────────────────────────────────────────────────────────────────────
router.get(
  '/bookings',
  verifyToken,
  asyncHandler(async (req, res) => {
    const userId = req.user.id;

    const result = await pool.query(
      `SELECT
         cb.id, cb.farm_issue_title, cb.description,
         cb.urgency_level, cb.escrow_amount, cb.escrow_status,
         cb.booking_status, cb.created_at, cb.updated_at,
         -- Expert info
         ep.id          AS expert_id,
         ep.specialty   AS expert_specialty,
         ep.hourly_rate AS expert_hourly_rate,
         ep.currency    AS expert_currency,
         js.full_name   AS expert_full_name,
         -- Client role indicator
         CASE WHEN cb.client_id = $1 THEN 'client' ELSE 'expert' END AS my_role
       FROM consultation_bookings cb
       JOIN expert_profiles ep      ON ep.id       = cb.expert_id
       JOIN job_seeker_profiles js  ON js.user_id  = ep.id
       WHERE cb.client_id = $1 OR cb.expert_id = $1
       ORDER BY cb.created_at DESC`,
      [userId]
    );

    return res.status(200).json({ success: true, data: result.rows });
  })
);

// ─────────────────────────────────────────────────────────────────────────────
// PATCH /api/agrilencer/bookings/:id/status
// Protected — update booking_status and/or escrow_status.
// Only the client or the expert involved can mutate a booking.
// Auto-disburse escrow when booking_status → 'completed'.
// ─────────────────────────────────────────────────────────────────────────────
router.patch(
  '/bookings/:id/status',
  verifyToken,
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!UUID_RE.test(id)) {
      return validationError(res, 'Booking ID must be a valid UUID.');
    }

    const { booking_status, escrow_status } = req.body;

    // Validate enums
    const VALID_BOOKING = ['requested', 'accepted', 'completed', 'cancelled'];
    const VALID_ESCROW  = ['pending_payment', 'held_in_escrow', 'disbursed', 'refunded'];

    if (booking_status && !VALID_BOOKING.includes(booking_status)) {
      return validationError(res, `"booking_status" must be one of: ${VALID_BOOKING.join(', ')}.`);
    }
    if (escrow_status && !VALID_ESCROW.includes(escrow_status)) {
      return validationError(res, `"escrow_status" must be one of: ${VALID_ESCROW.join(', ')}.`);
    }
    if (!booking_status && !escrow_status) {
      return validationError(res, 'Provide at least one of "booking_status" or "escrow_status".');
    }

    // ── Ownership check ───────────────────────────────────────────────────
    const booking = await pool.query(
      'SELECT client_id, expert_id, booking_status, escrow_status FROM consultation_bookings WHERE id = $1',
      [id]
    );
    if (booking.rows.length === 0) {
      return notFoundError(res, 'Booking not found.');
    }

    const record = booking.rows[0];
    const isClient = record.client_id === req.user.id;
    const isExpert = record.expert_id === req.user.id;

    if (!isClient && !isExpert) {
      return forbiddenError(res, 'Access denied. You are not a party to this booking.');
    }

    // ── Business rules ────────────────────────────────────────────────────
    // If completing, auto-disburse escrow regardless of request payload
    const finalEscrow =
      booking_status === 'completed' ? 'disbursed' : (escrow_status ?? record.escrow_status);
    const finalBooking = booking_status ?? record.booking_status;

    const result = await pool.query(
      `UPDATE consultation_bookings
       SET booking_status = $1,
           escrow_status  = $2,
           updated_at     = NOW()
       WHERE id = $3
       RETURNING id, client_id, expert_id, farm_issue_title, description,
                 urgency_level, escrow_amount, escrow_status, booking_status,
                 created_at, updated_at`,
      [finalBooking, finalEscrow, id]
    );

    return res.status(200).json({
      success: true,
      message: 'Booking status updated.',
      data: result.rows[0],
    });
  })
);

module.exports = router;
