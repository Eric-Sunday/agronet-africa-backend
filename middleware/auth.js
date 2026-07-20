'use strict';

const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'agronet-dev-secret-key-123';

// ─────────────────────────────────────────────────────────────────────────────
// verifyToken — validate JWT and attach decoded payload to req.user
// ─────────────────────────────────────────────────────────────────────────────
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized',
      message: 'Access denied. No token provided.',
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, email, role }
    next();
  } catch {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized',
      message: 'Invalid or expired token.',
    });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// requireRole — RBAC middleware factory
//
// Usage:
//   router.post('/api/jobs', verifyToken, requireRole(['employer']), handler)
//   router.post('/api/applications', verifyToken, requireRole(['job_seeker']), handler)
//
// Returns 403 Forbidden with a descriptive error message when the
// authenticated user's role is not in the allowedRoles array.
// ─────────────────────────────────────────────────────────────────────────────
const requireRole = (allowedRoles) => (req, res, next) => {
  const role = req.user?.role;

  if (!role || !allowedRoles.includes(role)) {
    // Build a specific human-readable denial message per context
    let message;
    if (allowedRoles.includes('employer') && !allowedRoles.includes('job_seeker')) {
      message = 'Access denied. Only registered employers can manage job listings.';
    } else if (allowedRoles.includes('job_seeker') && !allowedRoles.includes('employer')) {
      message = 'Access denied. Employers cannot apply for jobs.';
    } else {
      message = `Access denied. Required role: ${allowedRoles.join(' or ')}.`;
    }

    return res.status(403).json({
      success: false,
      error: 'Forbidden',
      message,
    });
  }

  next();
};

module.exports = { verifyToken, requireRole };
