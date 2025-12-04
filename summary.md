# Security Middleware Evaluation Summary

## Goals
We built a reusable Express.js middleware to block two top OWASP attacks:
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)

## Setup
We tested against two app modes:
1. `/vulnerable`: no protections (intentionally unsafe)
2. `/protected`: same features, but behind our middleware

We also ran load tests to measure latency overhead.

## Results (highlights)
- XSS:
  - `/vulnerable`: `<script>alert("XSS")</script>` executes, browser `alert()` fires.
  - `/protected`: same payload does NOT execute. CSP blocks inline script without nonce. No alert fired.
  - We captured screenshots (`capture-*.png`) and browser console logs (`console-*.txt`) showing the block.

- CSRF:
  - `/vulnerable`: forged POST (no token) succeeds.
    Example:  
    `curl -X POST http://localhost:3000/vulnerable/transfer -d "amount=999"` → **200 OK**
  - `/protected`: forged POST without token fails.
    Example:  
    `curl -X POST http://localhost:3000/protected/transfer -d "amount=999"` → **403 / 429**

- Performance:
  - `/vulnerable` ~1300 req/sec in our local Autocannon run
  - `/protected` ~330 req/sec in the same conditions  
  - ~3–4x slower under synthetic high load because we add:
    - session-backed CSRF validation,
    - nonce-based CSP,
    - origin checking,
    - rate limiting,
    - logging / auditing.

## Takeaway
The middleware stopped XSS and CSRF in our tests, and the tests are automated (`test/xss.test.js`, `test/csrf.test.js`).
There is some performance cost, which is expected for security.
This is realistic evidence, not just theory.
