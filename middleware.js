const crypto = require('crypto');

// Custom HTML escape function that escapes quotes too
function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

module.exports = function(options = {}) {
  const exemptPaths = options.exemptPaths || ['/exempt'];
  
  return function(req, res, next) {
    // ============================================
    // 1. GENERATE NONCE FOR CSP
    // ============================================
    res.locals.nonce = crypto.randomBytes(16).toString('base64');
    
    // ============================================
    // 2. GENERATE CSRF TOKEN (only if session exists)
    // ============================================
    if (req.session) {
      if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
      }
      res.locals.csrfToken = req.session.csrfToken;
    }
    
    // ============================================
    // 3. SET CONTENT SECURITY POLICY (STRICT - NO UNSAFE-INLINE)
    // ============================================
    res.setHeader('Content-Security-Policy',
      `default-src 'self'; ` +
      `script-src 'self' 'nonce-${res.locals.nonce}' https://cdn.jsdelivr.net; ` +
      `style-src 'self' https://cdn.jsdelivr.net; ` +  // REMOVED 'unsafe-inline'
      `object-src 'none'; ` +
      `base-uri 'self';`
    );
    
    // ============================================
    // 4. HTML ESCAPING FOR XSS PROTECTION
    // ============================================
    // Pre-escape query parameters
    if (req.query.userInput) {
      req.query.userInputEscaped = escapeHtml(req.query.userInput);
    }
    
    // ============================================
    // 5. CSRF TOKEN VALIDATION FOR STATE-CHANGING REQUESTS
    // ============================================
    // Only check POST, PUT, DELETE, PATCH
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
      // Check if path is exempted - FIXED to check full path
      const isExempt = exemptPaths.some(path => req.path.endsWith(path) || req.path.includes(path));
      
      if (!isExempt) {
        // Check if session exists
        if (!req.session || !req.session.csrfToken) {
          return res.status(403).json({ 
            error: 'CSRF token validation failed',
            message: 'No session or CSRF token found'
          });
        }
        
        // Get token from body, header, or cookie
        const token = req.body.csrfToken || 
                      req.headers['x-csrf-token'] || 
                      req.cookies['csrf-token'];
        
        // Validate token
        if (!token || token !== req.session.csrfToken) {
          return res.status(403).json({ 
            error: 'CSRF token validation failed',
            message: 'Invalid or missing CSRF token'
          });
        }
      }
    }
    
    next();
  };
};