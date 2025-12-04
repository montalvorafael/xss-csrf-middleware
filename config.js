<<<<<<< HEAD
// config.js
require('dotenv').config();

const isProd = process.env.NODE_ENV === 'production';

module.exports = {
  env: process.env.NODE_ENV || 'development',

  // Session / cookie
  sessionSecret: process.env.SESSION_SECRET || 'demo-session',
  cookie: {
    httpOnly: true,
    secure: isProd,        // set Secure only in production
    sameSite: 'lax',
    // no fixed domain here so it works in Docker / localhost / prod
  },

  // CSRF / security middleware options
  csrfExpiryMs: parseInt(process.env.CSRF_EXPIRY_MS || '1800000', 10), // 30 min
  doubleSubmit: process.env.DOUBLE_SUBMIT === 'true', // (placeholder if you later add stateless mode)
  csrfCookieName: process.env.CSRF_COOKIE_NAME || 'csrf-token',
  csrfHeaderName: process.env.CSRF_HEADER_NAME || 'x-csrf-token',

  allowedOrigins: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim())
    : ['http://localhost:3000'],

  rateLimit: {
    maxAttempts: parseInt(process.env.RATE_LIMIT_MAX || '10', 10),
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '15000', 10), // default 15s demo window
  },

  exemptPaths: process.env.EXEMPT_PATHS
    ? process.env.EXEMPT_PATHS.split(',').map(s => s.trim())
    : ['/protected/exempt'],

  port: parseInt(process.env.PORT || '3000', 10),
};
=======
// config.js
require('dotenv').config();

const isProd = process.env.NODE_ENV === 'production';

module.exports = {
  env: process.env.NODE_ENV || 'development',

  // Session / cookie
  sessionSecret: process.env.SESSION_SECRET || 'demo-session',
  cookie: {
    httpOnly: true,
    secure: isProd,        // set Secure only in production
    sameSite: 'lax',
    // no fixed domain here so it works in Docker / localhost / prod
  },

  // CSRF / security middleware options
  csrfExpiryMs: parseInt(process.env.CSRF_EXPIRY_MS || '1800000', 10), // 30 min
  doubleSubmit: process.env.DOUBLE_SUBMIT === 'true', // (placeholder if you later add stateless mode)
  csrfCookieName: process.env.CSRF_COOKIE_NAME || 'csrf-token',
  csrfHeaderName: process.env.CSRF_HEADER_NAME || 'x-csrf-token',

  allowedOrigins: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim())
    : ['http://localhost:3000'],

  rateLimit: {
    maxAttempts: parseInt(process.env.RATE_LIMIT_MAX || '10', 10),
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '15000', 10), // default 15s demo window
  },

  exemptPaths: process.env.EXEMPT_PATHS
    ? process.env.EXEMPT_PATHS.split(',').map(s => s.trim())
    : ['/protected/exempt'],

  port: parseInt(process.env.PORT || '3000', 10),
};
>>>>>>> 510a70b3c15fde540abd0533d41ac6087d3df44b
