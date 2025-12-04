// routes/vulnerable.js
const express = require('express');
const router = express.Router();

// Intentionally INSECURE demo routes
// This is your "this is what not to do" showcase.

router.get('/', (req, res) => {
  const userInput = req.query.userInput || '';
  // We do NOT escape here on purpose for the demo
  res.render('vulnerable', {
    userInput,
  });
});

// No CSRF, no validation
router.post('/transfer', (req, res) => {
  res.send(
    `<div class="alert alert-danger">Transferred $${req.body.amount || 0} (Vulnerable - forged requests work!)</div>`
  );
});

router.post('/change-password', (req, res) => {
  res.send(
    `<div class="alert alert-danger">Password changed to ${req.body.newPassword} (Vulnerable - forged requests work!)</div>`
  );
});

module.exports = router;
