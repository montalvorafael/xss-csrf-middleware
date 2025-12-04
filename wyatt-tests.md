<<<<<<< HEAD
# Wyatt CSRF Tests Log

## Unit Tests
- Run `npm test`: 4/4 passing
  - Validates good token via form
  - Rejects invalid token
  - Rejects missing token
  - Validates AJAX with x-csrf-token header

## Manual Tests
- Forge transfer: `curl -X POST http://localhost:3000/protected/transfer -d "amount=999"` → 403 Invalid CSRF token
- Forge PW change: `curl -X POST http://localhost:3000/protected/change-password -d "newPassword=hacked"` → 403 Invalid CSRF token
- Legit transfer: Use form on /protected → Success
- AJAX transfer: Check console on /protected → AJAX Transfer: Transferred $50 (Protected - requires valid token!)
- SameSite test: Open forge.html in browser (file://), submit → Blocked by SameSite

## Coverage
- Token generation: ✓
- Expiry: ✓ (tested invalid, actual expiry requires time)
- Validation: body, header, cookie ✓
=======
# Wyatt CSRF Tests Log

## Unit Tests
- Run `npm test`: 4/4 passing
  - Validates good token via form
  - Rejects invalid token
  - Rejects missing token
  - Validates AJAX with x-csrf-token header

## Manual Tests
- Forge transfer: `curl -X POST http://localhost:3000/protected/transfer -d "amount=999"` → 403 Invalid CSRF token
- Forge PW change: `curl -X POST http://localhost:3000/protected/change-password -d "newPassword=hacked"` → 403 Invalid CSRF token
- Legit transfer: Use form on /protected → Success
- AJAX transfer: Check console on /protected → AJAX Transfer: Transferred $50 (Protected - requires valid token!)
- SameSite test: Open forge.html in browser (file://), submit → Blocked by SameSite

## Coverage
- Token generation: ✓
- Expiry: ✓ (tested invalid, actual expiry requires time)
- Validation: body, header, cookie ✓
>>>>>>> 510a70b3c15fde540abd0533d41ac6087d3df44b
- Stateless double-submit: Implemented, not tested yet