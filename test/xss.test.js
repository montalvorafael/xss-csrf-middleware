/* eslint-env mocha, node, browser */
/* global window, document */
/*xss.test.js - FINAL FIXED VERSION*/
const chai = require('chai');
const expect = chai.expect;
const request = require('supertest');
const puppeteer = require('puppeteer');
const app = require('../app');

describe('XSS Rafael Tests - Enhanced', function () {
  this.timeout(30000);

  // Expanded payload categories
  const PAYLOADS = {
    basic: [
      '<script>alert("XSS")</script>',
      '<script>alert(1)</script>',
      '<script src="http://evil.com/xss.js"></script>'
    ],
    eventHandlers: [
      '"><img src=x onerror=alert("XSS")>',
      '<img src=x onerror=alert(1)>',
      '<body onload=alert("XSS")>',
      '<input onfocus=alert(1) autofocus>',
      '<select onfocus=alert(1) autofocus>',
      '<textarea onfocus=alert(1) autofocus>',
      '<iframe onload=alert(1)>',
      '<svg onload=alert(1)>'
    ],
    javascript: [
      'javascript:alert("XSS")',
      '<a href="javascript:alert(1)">Click</a>',
      '<form action="javascript:alert(1)"><input type="submit"></form>',
      '<object data="javascript:alert(1)">',
      '<embed src="javascript:alert(1)">'
    ],
    htmlInjection: [
      '<b>bold</b>',
      '<iframe src="http://evil.com"></iframe>',
      '<object data="http://evil.com"></object>',
      '<embed src="http://evil.com">',
      '<link rel="stylesheet" href="http://evil.com/xss.css">'
    ],
    encoding: [
      '&#60;script&#62;alert(1)&#60;/script&#62;',
      '&lt;script&gt;alert(1)&lt;/script&gt;',
      '%3Cscript%3Ealert(1)%3C/script%3E',
      '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
      '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e'
    ],
    dataUri: [
      '<iframe src="data:text/html,<script>alert(1)</script>">',
      '<object data="data:text/html,<script>alert(1)</script>">',
      '<embed src="data:text/html,<script>alert(1)</script>">'
    ],
    svg: [
      '<svg><script>alert(1)</script></svg>',
      '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
      '<svg><set onbegin=alert(1) attributeName=x to=0>'
    ],
    meta: [
      '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
      '<meta http-equiv="refresh" content="0;url=data:text/html,<script>alert(1)</script>">'
    ],
    css: [
      '<style>@import "http://evil.com/xss.css";</style>',
      '<div style="background:url(javascript:alert(1))">',
      '<style>body{background:url("javascript:alert(1)")}</style>'
    ]
  };

  let browser;
  let server;
  let baseUrl;

  before(async function () {
    server = app.listen(0);
    baseUrl = `http://localhost:${server.address().port}`;
    browser = await puppeteer.launch({ 
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
  });

  after(async function () {
    if (browser) await browser.close();
    if (server) await new Promise(r => server.close(r));
  });

  async function visitWithPayload(path, payload) {
    const page = await browser.newPage();

    await page.evaluateOnNewDocument(() => {
      window.__XSS_ALERTS = 0;
      window.__XSS_BLOCKED = false;
      window.alert = () => { window.__XSS_ALERTS += 1; };
      window.addEventListener('securitypolicyviolation', () => { window.__XSS_BLOCKED = true; });
    });

    try {
      await page.goto(`${baseUrl}${path}?userInput=${encodeURIComponent(payload)}`, {
        waitUntil: 'networkidle2',
        timeout: 10000
      });

      const fired = await page.evaluate(() => window.__XSS_ALERTS);
      const blocked = await page.evaluate(() => window.__XSS_BLOCKED);
      const h1Text = await page.evaluate(() => {
        const h = document.querySelector('h1');
        return h ? h.textContent || '' : '';
      });
      const h1Html = await page.evaluate(() => {
        const h = document.querySelector('h1');
        return h ? h.innerHTML || '' : '';
      });
      const bodyHtml = await page.evaluate(() => document.body.innerHTML.substring(0, 500));

      await page.close();
      return { fired, blocked, h1Text, h1Html, bodyHtml };
    } catch (error) {
      await page.close();
      throw error;
    }
  }

  // Helper to check if content is properly escaped
  function isContentEscaped(html) {
    return html.includes('&lt;') || html.includes('&gt;') || 
           html.includes('&quot;') || html.includes('&#39;') ||
           html.includes('&#60;') || html.includes('&#62;');
  }

  // Helper to check if dangerous patterns exist unescaped
  function hasDangerousUnescapedContent(html, payload) {
    // If content is escaped, it's safe
    if (isContentEscaped(html)) {
      return false;
    }
    // Check for dangerous unescaped patterns
    return (
      (/<script(?![^>]*nonce)[^>]*>/i.test(html) && !html.includes('&lt;script')) ||
      (/\son\w+\s*=/i.test(html)) ||
      (/href\s*=\s*["']?javascript:/i.test(html))
    );
  }

  describe('Basic XSS Protection', () => {
    it('blocks all basic script injections on protected route', async function () {
      for (const payload of PAYLOADS.basic) {
        const { fired, blocked, bodyHtml } = await visitWithPayload('/protected', payload);
        expect(fired, `Script executed with payload: ${payload}`).to.equal(0);
        // Content should be escaped OR CSP should block it
        expect(blocked || isContentEscaped(bodyHtml), `Script not blocked: ${payload}`).to.be.true;
      }
    });

    it('allows benign HTML on protected route without executing', async function () {
      const { fired, bodyHtml } = await visitWithPayload('/protected', PAYLOADS.htmlInjection[0]);
      expect(fired).to.equal(0);
      expect(bodyHtml).to.include('&lt;b&gt;'); // Should be escaped
    });
  });

  describe('Event Handler XSS Protection', () => {
    it('blocks all event handler injections on protected route', async function () {
      for (const payload of PAYLOADS.eventHandlers) {
        const { fired, bodyHtml } = await visitWithPayload('/protected', payload);
        expect(fired, `Event handler executed: ${payload}`).to.equal(0);
        // Content should be escaped (no dangerous unescaped patterns)
        expect(hasDangerousUnescapedContent(bodyHtml, payload), 
               `Event handler not escaped: ${payload}`).to.be.false;
      }
    });
  });

  describe('JavaScript Protocol Protection', () => {
    it('blocks javascript: protocol injections on protected route', async function () {
      for (const payload of PAYLOADS.javascript) {
        const { fired, bodyHtml } = await visitWithPayload('/protected', payload);
        expect(fired, `javascript: protocol executed: ${payload}`).to.equal(0);
        // Content should be escaped (no dangerous unescaped patterns)
        expect(hasDangerousUnescapedContent(bodyHtml, payload), 
               `javascript: protocol not sanitized: ${payload}`).to.be.false;
      }
    });
  });

  describe('Encoding Attack Protection', () => {
    it('blocks encoded XSS attempts on protected route', async function () {
      for (const payload of PAYLOADS.encoding) {
        const { fired } = await visitWithPayload('/protected', payload);
        expect(fired, `Encoded payload executed: ${payload}`).to.equal(0);
      }
    });
  });

  describe('Data URI Protection', () => {
    it('blocks data: URI XSS attempts on protected route', async function () {
      for (const payload of PAYLOADS.dataUri) {
        const { fired, bodyHtml } = await visitWithPayload('/protected', payload);
        expect(fired, `Data URI executed: ${payload}`).to.equal(0);
        expect(hasDangerousUnescapedContent(bodyHtml, payload),
               `Data URI not sanitized: ${payload}`).to.be.false;
      }
    });
  });

  describe('SVG-based XSS Protection', () => {
    it('blocks SVG XSS vectors on protected route', async function () {
      for (const payload of PAYLOADS.svg) {
        const { fired, bodyHtml } = await visitWithPayload('/protected', payload);
        expect(fired, `SVG XSS executed: ${payload}`).to.equal(0);
        expect(hasDangerousUnescapedContent(bodyHtml, payload),
               `SVG XSS not blocked: ${payload}`).to.be.false;
      }
    });
  });

  describe('Meta Tag Protection', () => {
    it('blocks meta refresh XSS on protected route', async function () {
      for (const payload of PAYLOADS.meta) {
        const { fired, bodyHtml } = await visitWithPayload('/protected', payload);
        expect(fired, `Meta refresh executed: ${payload}`).to.equal(0);
        expect(hasDangerousUnescapedContent(bodyHtml, payload),
               `Meta tag not sanitized: ${payload}`).to.be.false;
      }
    });
  });

  describe('CSS-based XSS Protection', () => {
    it('blocks CSS injection XSS on protected route', async function () {
      for (const payload of PAYLOADS.css) {
        const { fired, bodyHtml } = await visitWithPayload('/protected', payload);
        expect(fired, `CSS XSS executed: ${payload}`).to.equal(0);
        expect(hasDangerousUnescapedContent(bodyHtml, payload),
               `CSS injection not sanitized: ${payload}`).to.be.false;
      }
    });
  });

  describe('CSP Implementation', () => {
    it('page includes at least one <script nonce="..."> on protected route', async function () {
      const page = await browser.newPage();
      await page.goto(`${baseUrl}/protected`);

      const hasNonceScript = await page.evaluate(() => {
        const el = document.querySelector('script[nonce]');
        return !!el;
      });

      await page.close();
      expect(hasNonceScript).to.equal(true);
    });

    it('blocks inline script without nonce on protected route', async function () {
      const page = await browser.newPage();

      await page.evaluateOnNewDocument(() => {
        window.__XSS_ALERTS = 0;
        window.alert = () => { window.__XSS_ALERTS += 1; };
      });

      await page.goto(`${baseUrl}/protected`);

      const fired = await page.evaluate(() => {
        const s = document.createElement('script');
        s.textContent = 'alert("Blocked XSS");';
        document.head.appendChild(s);
        return window.__XSS_ALERTS;
      });

      await page.close();
      expect(fired).to.equal(0);
    });

    it('CSP header is set and strict on protected responses', async function () {
      const res = await request(app).get('/protected');
      const csp = res.headers['content-security-policy'];
      
      expect(csp).to.be.a('string');
      expect(csp).to.include("'nonce-");
      expect(csp).to.include("script-src");
      expect(csp).to.include("object-src 'none'");
      expect(csp).to.not.include("'unsafe-inline'");
      expect(csp).to.not.include("'unsafe-eval'");
    });

    it('browser reports CSP violation when inline script without nonce is injected', async function () {
      const page = await browser.newPage();

      await page.evaluateOnNewDocument(() => {
        window.__XSS_BLOCKED = false;
        window.addEventListener('securitypolicyviolation', () => { window.__XSS_BLOCKED = true; });
      });

      await page.goto(`${baseUrl}/protected?userInput=safe`);

      const violations = await page.evaluate(() => window.__XSS_BLOCKED || false);
      await page.close();

      expect(violations).to.equal(true);
    });

    it('CSP includes all required security directives', async function () {
      const res = await request(app).get('/protected');
      const csp = res.headers['content-security-policy'];
      
      expect(csp).to.include("default-src 'self'");
      expect(csp).to.include("base-uri 'self'");
      expect(csp).to.include("object-src 'none'");
      expect(csp).to.match(/script-src 'self' 'nonce-[a-zA-Z0-9+/=]+'/);
    });
  });

  describe('Vulnerable Route Baseline Tests', () => {
    it('vulnerable route allows reflected XSS (baseline for demo)', async function () {
      for (const payload of PAYLOADS.basic) {
        const { fired, h1Text } = await visitWithPayload('/vulnerable', payload);
        expect(fired, `XSS did not fire on vulnerable route: ${payload}`).to.be.greaterThan(0);
        expect(h1Text.toLowerCase()).to.include('echo');
      }
    });

    it('vulnerable route renders raw unsanitized HTML (for demo comparison)', async function () {
      const { h1Html } = await visitWithPayload('/vulnerable', '<b>raw</b>');
      expect(h1Html).to.include('<b>raw</b>');
    });

    it('vulnerable route has no CSP header', async function () {
      const res = await request(app).get('/vulnerable');
      expect(res.headers['content-security-policy']).to.be.undefined;
    });
  });

  describe('Edge Cases and Special Scenarios', () => {
    it('handles empty input without errors', async function () {
      const { fired } = await visitWithPayload('/protected', '');
      expect(fired).to.equal(0);
    });

    it('handles very long payloads without errors', async function () {
      const longPayload = '<script>alert(1)</script>'.repeat(100);
      const { fired } = await visitWithPayload('/protected', longPayload);
      expect(fired).to.equal(0);
    });

    it('handles special characters and unicode', async function () {
      const unicodePayload = '<script>alert("XSS\u2028\u2029")</script>';
      const { fired } = await visitWithPayload('/protected', unicodePayload);
      expect(fired).to.equal(0);
    });

    it('handles null bytes in payload', async function () {
      const nullBytePayload = '<script\x00>alert(1)</script>';
      const { fired } = await visitWithPayload('/protected', nullBytePayload);
      expect(fired).to.equal(0);
    });

    it('handles mixed case HTML tags', async function () {
      const mixedCase = '<ScRiPt>alert(1)</sCrIpT>';
      const { fired } = await visitWithPayload('/protected', mixedCase);
      expect(fired).to.equal(0);
    });
  });

  describe('HTML Escaping Validation', () => {
    it('escapes < character correctly', async function () {
      const { bodyHtml } = await visitWithPayload('/protected', '<');
      expect(bodyHtml).to.include('&lt;');
    });

    it('escapes > character correctly', async function () {
      const { bodyHtml } = await visitWithPayload('/protected', '>');
      expect(bodyHtml).to.include('&gt;');
    });

    it('escapes & character correctly', async function () {
      const { bodyHtml } = await visitWithPayload('/protected', '&');
      expect(bodyHtml).to.include('&amp;');
    });

    // FIXED: Check raw HTTP response instead of innerHTML (browser decodes entities)
    it('escapes " character correctly', async function () {
      const res = await request(app).get('/protected?userInput=test"quote');
      // Check raw HTTP response for escaped double quote
      expect(res.text).to.include('&quot;');
    });

    // FIXED: Check raw HTTP response instead of innerHTML (browser decodes entities)
    it('escapes \' character correctly', async function () {
      const res = await request(app).get("/protected?userInput=test'quote");
      // Check raw HTTP response for escaped single quote
      expect(res.text).to.include('&#39;');
    });
  });

  describe('Nonce Generation', () => {
    it('generates unique nonces for each request', async function () {
      const res1 = await request(app).get('/protected');
      const res2 = await request(app).get('/protected');
      
      const nonce1 = res1.headers['content-security-policy'].match(/nonce-([a-zA-Z0-9+/=]+)/)[1];
      const nonce2 = res2.headers['content-security-policy'].match(/nonce-([a-zA-Z0-9+/=]+)/)[1];
      
      expect(nonce1).to.not.equal(nonce2);
    });

    it('nonce is sufficiently long and random', async function () {
      const res = await request(app).get('/protected');
      const nonce = res.headers['content-security-policy'].match(/nonce-([a-zA-Z0-9+/=]+)/)[1];
      
      expect(nonce.length).to.be.at.least(16);
      expect(nonce).to.match(/^[a-zA-Z0-9+/=]+$/);
    });
  });
});