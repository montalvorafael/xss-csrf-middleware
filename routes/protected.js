// routes/protected.js
const express = require('express');
const { body, validationResult } = require('express-validator');

module.exports = function buildProtectedRouter(logger) {
  const router = express.Router();

  // Safe page: CSRF token + nonce provided by middleware in res.locals
  router.get('/', (req, res) => {
    res.render('protected', {
      csrfToken: res.locals.csrfToken,
      nonce: res.locals.nonce,
    });
  });

  // Protected money transfer
  router.post(
    '/transfer',
    [
      body('amount')
        .isNumeric().withMessage('Amount must be a number')
        .isFloat({ min: 0 }).withMessage('Amount must be positive'),
    ],
    (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        logger.warn('VALIDATION_FAIL_TRANSFER', {
          ip: req.ip,
          ua: req.get('user-agent'),
          path: req.path,
          errors: errors.array(),
        });
        return res.status(400).json({ errors: errors.array() });
      }

      return res.send(
        `<div class="alert alert-success">Transferred $${req.body.amount || 0} (Protected - requires valid token!)</div>`
      );
    }
  );

  // Protected password change
  router.post(
    '/change-password',
    [
      body('newPassword')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long'),
    ],
    (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        logger.warn('VALIDATION_FAIL_PASSWORD', {
          ip: req.ip,
          ua: req.get('user-agent'),
          path: req.path,
          errors: errors.array(),
        });
        return res.status(400).json({ errors: errors.array() });
      }

      return res.send(
        `<div class="alert alert-success">Password changed to ${req.body.newPassword} (Protected - requires valid token!)</div>`
      );
    }
  );

  // Exempt path example (webhook / public callback)
  router.post('/exempt', (req, res) => {
    // CSRF middleware skips CSRF validation on this path if it's in exemptPaths
    res.send(
      `<div class="alert alert-info">Exempted route - no CSRF check</div>`
    );
  });

  return router;
};
