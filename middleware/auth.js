const jwt = require('jsonwebtoken');

/**
 * Middleware to verify JWT tokens and protect routes.
 * Expects the token in the Authorization header as: Bearer <token>
 */
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
    // Note: ensure JWT_SECRET is set in your .env
    const secret = process.env.JWT_SECRET || 'agronet-dev-secret-key-123';
    const decoded = jwt.verify(token, secret);
    
    // Attach the decoded user payload to the request object
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized',
      message: 'Invalid or expired token.',
    });
  }
};

module.exports = { verifyToken };
