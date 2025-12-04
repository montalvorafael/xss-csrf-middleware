# XSS–CSRF Middleware


A simple, reusable **Express middleware** for defending against **Cross-Site Scripting (XSS)** and **Cross-Site Request Forgery (CSRF)** attacks.

---

##  Features

### XSS Protection
- Enforces **Content-Security-Policy (CSP)** with unique per-request nonces
- Escapes all HTML output using `escape-html`
- Blocks inline scripts unless a valid nonce is attached
- Side-by-side `/vulnerable` vs `/protected` demo routes

### CSRF Protection
- **256-bit secure tokens** (session-based or stateless double-submit)
- Tokens expire every **30 minutes** with automatic rotation
- Validates from **body**, **header**, or **cookie**
- Supports `doubleSubmit: true` for stateless apps
- Customizable cookie & header names
- Optional **origin/referrer validation**
- Built-in **rate limiting** of invalid attempts
- **Exempt paths** for webhooks & public APIs

---

##  Quick Start

```bash
npm install
npm start
```

### Basic Usage

```javascript
const express = require('express');
const securityMiddleware = require('./middleware');

const app = express();

app.use('/protected', securityMiddleware({
  csrfExpiryMs: 30 * 60 * 1000,   // 30 minutes
  doubleSubmit: false             // set true for stateless mode
}));

app.listen(3000);
```

### Form Integration

```html
<form action="/protected/transfer" method="POST">
  <input type="hidden" name="csrfToken" value="<%= csrfToken %>">
  <input type="number" name="amount">
  <button type="submit">Transfer</button>
</form>
```

---

## Demo Routes

| Route | Protection | Behavior |
|-------|------------|----------|
| `/vulnerable` | ❌ None | XSS executes, CSRF succeeds |
| `/protected` | ✅ Enabled | XSS blocked by CSP, CSRF returns 403 |

### Try It

```
# XSS Test
http://localhost:3000/vulnerable?userInput=<script>alert("XSS")</script>  → alert fires
http://localhost:3000/protected?userInput=<script>alert("XSS")</script>   → blocked & escaped

# CSRF Test
curl -X POST http://localhost:3000/vulnerable/transfer -d "amount=999"    → succeeds
curl -X POST http://localhost:3000/protected/transfer -d "amount=999"     → 403 Forbidden
```

---

##  Testing

```bash
npm test          # Run Mocha + Chai tests
npm run coverage  # Istanbul coverage report
npm run lint      # ESLint
npm run benchmark # Performance + attack suite
```

### Test Coverage Includes
- Token generation & expiry
- Header / body / cookie validation
- Stateless (double-submit) mode
- Rate limiting behavior
- Path exemptions
- Origin validation
- CSP nonce enforcement

---

##  Evidence of Effectiveness

Automated Puppeteer tests capture proof of protection:

| File | Result |
|------|--------|
| `alerts-vulnerable.json` | `["XSS", "Inline script runs!"]` — attack succeeded |
| `alerts-protected.json` | `[]` — no alerts, attack blocked |
| `console-protected.txt` | CSP violation reports logged |
| `capture-vulnerable.png` | Screenshot showing alert popup |
| `capture-protected.png` | Screenshot showing escaped payload |

---

##  Configuration

All options can be set via **JavaScript object** or **environment variables**.

### Environment Variables

```env
SESSION_SECRET=your-super-secret-here
CSRF_EXPIRY_MS=1800000
DOUBLE_SUBMIT=false
CSRF_COOKIE_NAME=csrf-token
CSRF_HEADER_NAME=x-csrf-token
ALLOWED_ORIGINS=http://localhost:3000,https://yourapp.com
RATE_LIMIT_MAX=10
RATE_LIMIT_WINDOW_MS=900000
EXEMPT_PATHS=/webhook,/api/public
CSP_NONCE_ENABLED=true
ESCAPE_HTML_ENABLED=true
```

### JavaScript Options

```javascript
securityMiddleware({
  csrfExpiryMs: 30 * 60 * 1000,
  doubleSubmit: false,
  csrfCookieName: 'csrf-token',
  csrfHeaderName: 'x-csrf-token',
  allowedOrigins: ['http://localhost:3000'],
  rateLimit: {
    maxAttempts: 10,
    windowMs: 900000
  },
  exemptPaths: ['/api/webhook', '/api/public'],
  tokenGenerator: null  // custom function, or null for default
});
```

| Option | Description | Default |
|--------|-------------|---------|
| `csrfExpiryMs` | Token expiry time (ms) | `1800000` (30 min) |
| `doubleSubmit` | Enable stateless mode | `false` |
| `csrfCookieName` | Cookie name | `csrf-token` |
| `csrfHeaderName` | Header name | `x-csrf-token` |
| `allowedOrigins` | Allowed origins for validation | `[]` |
| `rateLimit.maxAttempts` | Max invalid attempts | `10` |
| `rateLimit.windowMs` | Rate limit window (ms) | `900000` |
| `exemptPaths` | Paths to skip CSRF check | `[]` |

---

##  Docker

```bash
# Using docker-compose
docker-compose up --build

# Or manually
docker build -t xss-csrf-middleware .
docker run -p 3000:3000 xss-csrf-middleware
```

---

##  Manual Testing Guide

1. **Start the server**
   ```bash
   node app.js
   ```

2. **Test CSRF protection**
   ```bash
   # Without token → blocked
   curl -X POST http://localhost:3000/protected/transfer -d "amount=999"
   
   # With valid token → succeeds
   curl -X POST http://localhost:3000/protected/transfer \
     -H "x-csrf-token: <your-token>" \
     -d "amount=999"
   ```

3. **Test XSS protection**
   - Visit `/vulnerable?userInput=<script>alert(1)</script>` → alert fires
   - Visit `/protected?userInput=<script>alert(1)</script>` → escaped, no alert

4. **Test cross-site attacks**
   - Open `forge.html` locally (`file://`)
   - Attempt to submit to `/protected` → blocked by SameSite + CSP

5. **Test rate limiting**
   - Make 10+ invalid CSRF requests quickly → 429 Too Many Requests

6. **Test exempt paths**
   - POST to an exempt path without token → succeeds

---

##  Project Structure

```
xss-csrf-middleware/
├── app.js                 # Demo Express app
├── middleware/
│   ├── index.js           # Main middleware export
│   ├── csrf.js            # CSRF protection logic
│   ├── xss.js             # XSS protection logic
│   └── utils.js           # Helper functions
├── test/
│   ├── csrf.test.js       # CSRF unit tests
│   └── xss.test.js        # XSS unit tests
├── benchmark.js           # Performance testing
├── capture_csp_and_console.js  # Puppeteer evidence capture
├── forge.html             # Cross-site attack demo
├── reports/               # Benchmark output
├── docker-compose.yml
├── Dockerfile
└── README.md
```

---

##  References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---



