const express = require('express');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const cookieParser = require('cookie-parser');
require('dotenv').config();

const securityMiddleware = require('./middleware');

const app = express();
const PORT = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use(session({
  secret: process.env.SESSION_SECRET || 'steamdeck-2025',
  resave: false,
  saveUninitialized: false,
  store: new MemoryStore(),
  cookie: { httpOnly: true, sameSite: 'strict' }
}));

// Custom HTML escape function (same as middleware)
function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ============================================
// VULNERABLE ROUTES (NO PROTECTION)
// ============================================
app.get('/vulnerable', (req, res) => {
  const userInput = req.query.userInput || '';
  // INTENTIONALLY UNSAFE - No escaping, direct injection
  res.send(`<h1>Vulnerable Echo: ${userInput}</h1><script>alert('Inline script runs!')</script>`);
});

app.post('/vulnerable/transfer', (req, res) => {
  res.send('Transfer successful (no protection)');
});

// ============================================
// PROTECTED ROUTES (WITH MIDDLEWARE)
// ============================================
app.use('/protected', securityMiddleware());

app.get('/protected', (req, res) => {
  // Get user input and escape it for XSS protection
  const userInputRaw = req.query.userInput || '';
  const userInput = escapeHtml(userInputRaw);
  
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
      </head>
      <body class="container mt-5">
        <div class="card">
          <div class="card-header bg-success text-white"><h2>Protected Page</h2></div>
          <div class="card-body">
            <h1 class="alert alert-success">Safe Echo: ${userInput}</h1>
            <form method="POST" action="/protected/transfer">
              <input name="amount" value="100" class="form-control mb-2">
              <input type="hidden" name="csrfToken" value="${res.locals.csrfToken || ''}">
              <button class="btn btn-primary">Transfer</button>
            </form>
            <script nonce="${res.locals.nonce || ''}">console.log('Safe script with nonce');</script>
            <script>alert('This should be blocked by CSP!');</script>
          </div>
        </div>
      </body>
    </html>
  `);
});

app.post('/protected/transfer', (req, res) => {
  res.send('Transfer successful (protected)');
});

app.post('/protected/change-password', (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ errors: ['Password must be at least 8 characters'] });
  }
  res.send('Password changed successfully');
});

app.post('/protected/exempt', (req, res) => {
  res.send('Exempted route - no CSRF required');
});

// Only start server if run directly (not when required by tests)
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
}

module.exports = app;
