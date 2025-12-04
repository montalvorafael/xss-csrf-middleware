/* eslint-env node, browser */
/* global window */
const fs = require('fs');
const puppeteer = require('puppeteer');

const BASE = 'http://localhost:3000';
const XSS_PAYLOAD = '<script>window.__EVIDENCE_XSS_FIRED=1;alert("EVIDENCE XSS")</script>';
const encodedPayload = encodeURIComponent(XSS_PAYLOAD);

(async () => {
  const out = [];
  const browser = await puppeteer.launch({ headless: true });
  try {
    const page = await browser.newPage();

    // 1) Vulnerable page: should execute inline script -> set window.__EVIDENCE_XSS_FIRED
    await page.evaluateOnNewDocument(() => {
      // override alert to avoid blocking; but still set a flag
      window.alert = () => { window.__EVIDENCE_XSS_ALERT = (window.__EVIDENCE_XSS_ALERT || 0) + 1; };
    });
    const vulnUrl = `${BASE}/vulnerable?userInput=${encodedPayload}`;
    await page.goto(vulnUrl, { waitUntil: 'networkidle2' });
    await page.screenshot({ path: 'vulnerable.png', fullPage: true });
    const vulnFlag = await page.evaluate(() => ({ fired: !!window.__EVIDENCE_XSS_FIRED, alerts: window.__EVIDENCE_XSS_ALERT || 0 }));
    out.push(`VULNERABLE PAGE: ${vulnUrl}`);
    out.push(`  - screenshot: vulnerable.png`);
    out.push(`  - xss fired flag: ${JSON.stringify(vulnFlag)}`);

    // 2) Protected page: script should NOT execute
    const protUrl = `${BASE}/protected?userInput=${encodedPayload}`;
    await page.goto(protUrl, { waitUntil: 'networkidle2' });
    await page.screenshot({ path: 'protected.png', fullPage: true });
    const protFlag = await page.evaluate(() => ({ fired: !!window.__EVIDENCE_XSS_FIRED, alerts: window.__EVIDENCE_XSS_ALERT || 0 }));
    out.push(`PROTECTED PAGE: ${protUrl}`);
    out.push(`  - screenshot: protected.png`);
    out.push(`  - xss fired flag: ${JSON.stringify(protFlag)}`);

    // 3) Forged POST to vulnerable/transfer (should succeed)
    const forgeVuln = await page.evaluate(async () => {
      const resp = await fetch('/vulnerable/transfer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'amount=999'
      });
      const text = await resp.text();
      return { status: resp.status, text: text.slice(0, 500) };
    });
    out.push('FORGE POST TO /vulnerable/transfer (no token)');
    out.push(`  - status: ${forgeVuln.status}`);
    out.push(`  - body (truncated): ${forgeVuln.text}`);

    // 4) Forged POST to protected/transfer (no token) => should be blocked (403/429)
    const forgeProt = await page.evaluate(async () => {
      const resp = await fetch('/protected/transfer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Origin': window.location.origin },
        body: 'amount=999'
      });
      const text = await resp.text();
      return { status: resp.status, text: text.slice(0, 500) };
    });
    out.push('FORGE POST TO /protected/transfer (no token)');
    out.push(`  - status: ${forgeProt.status}`);
    out.push(`  - body (truncated): ${forgeProt.text}`);

    // Write evidence summary
    fs.writeFileSync('evidence.txt', out.join('\n') + '\n', 'utf8');
    console.log('Evidence collected: vulnerable.png, protected.png, evidence.txt');
    console.log(fs.readFileSync('evidence.txt', 'utf8'));
  } catch (err) {
    console.error('Error collecting evidence', err);
  } finally {
    await browser.close();
  }
})();
