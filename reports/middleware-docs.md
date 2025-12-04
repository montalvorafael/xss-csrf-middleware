# Middleware Architecture: XSS + CSRF Protection

## Overview
The middleware stack integrates XSS sanitization and CSRF token validation into a unified Express layer.  
Each request passes through both layers before reaching route handlers.

---

## 🧩 Components

### 1. Helmet + CSP
- Uses `helmet.contentSecurityPolicy()` to enforce:
  ```js
  default-src 'none';
  script-src 'self' 'nonce-{RANDOM_NONCE}';
  style-src 'self';
  connect-src 'self';
