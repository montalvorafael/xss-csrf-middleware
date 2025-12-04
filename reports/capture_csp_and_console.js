/* eslint-env node, browser */
/* global window */
/*capture_csp_and_console.js*/
/* eslint-env node, browser */
/* global document */
const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

(async () => {
  console.log('Starting capture script...');
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();

  async function capture(url, name) {
    try {
      console.log(`Visiting ${url}`);
      await page.evaluateOnNewDocument(() => {
        window.alert = () => { window.__CAP_ALERTS = (window.__CAP_ALERTS || 0) + 1; };
        window.__CSP_VIOLATIONS = [];
        window.addEventListener('securitypolicyviolation', ev => {
          window.__CSP_VIOLATIONS.push({
            blockedURI: ev.blockedURI,
            violatedDirective: ev.violatedDirective,
            effectiveDirective: ev.effectiveDirective,
            originalPolicy: ev.originalPolicy
          });
        });
      });

      await page.goto(url, { waitUntil: 'networkidle2' });

      const screenshotPath = path.join(__dirname, `capture-${name}.png`);
      await page.screenshot({ path: screenshotPath, fullPage: true });
      console.log(`Saved screenshot: ${path.basename(screenshotPath)}`);

      const html = await page.content();
      fs.writeFileSync(path.join(__dirname, `${name}.html`), html);
      console.log(`Saved HTML: ${name}.html`);

      const csp = await page.evaluate(() => window.__CSP_VIOLATIONS || []);
      fs.writeFileSync(path.join(__dirname, `csp-${name}.json`), JSON.stringify(csp, null, 2));
      console.log(`Saved CSP violations: csp-${name}.json`);

      const alerts = await page.evaluate(() => window.__CAP_ALERTS || 0);
      fs.writeFileSync(path.join(__dirname, `alerts-${name}.json`), JSON.stringify({ alerts }, null, 2));
      console.log(`Saved alerts record: alerts-${name}.json`);

      const logs = await page.evaluate(() => {
        try {
          return (window.__console_log_capture || []);
        } catch (e) {
          return [];
        }
      });
      fs.writeFileSync(path.join(__dirname, `console-${name}.txt`), logs.join('\n'));
      console.log(`Saved console log: console-${name}.txt`);
    } catch (err) {
      console.error('Error during capture:', err);
    }
  }

  await capture('http://localhost:3000/vulnerable?userInput=<script>alert("XSS")</script>', 'vulnerable');
  await capture('http://localhost:3000/protected?userInput=<script>alert("XSS")</script>', 'protected');

  await browser.close();
  console.log('All captures complete. Files created:');
  console.log('- capture-vulnerable.png, capture-protected.png');
  console.log('- vulnerable.html, protected.html');
  console.log('- csp-vulnerable.json, csp-protected.json');
  console.log('- alerts-vulnerable.json, alerts-protected.json');
  console.log('- console-vulnerable.txt, console-protected.txt');
})();
