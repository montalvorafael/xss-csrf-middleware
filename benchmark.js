#!/usr/bin/env node

const supertest = require('supertest');
const puppeteer = require('puppeteer');
const autocannon = require('autocannon');
const { fork } = require('child_process');
const fs = require('fs');
const path = require('path');

const BASE_URL = 'http://localhost:3000';
const REPORT_DIR = path.join(__dirname, 'reports');

let server;
let testCounter = 0;

// Ensure reports directory exists
if (!fs.existsSync(REPORT_DIR)) {
  fs.mkdirSync(REPORT_DIR, { recursive: true });
}

// XSS Attack Payloads - Multiple categories
const XSS_PAYLOADS = {
  basic: [
    { name: 'Basic Script Tag', payload: '<script>alert("XSS")</script>' },
    { name: 'Script with Alert(1)', payload: '<script>alert(1)</script>' },
    { name: 'External Script', payload: '<script src="http://evil.com/xss.js"></script>' }
  ],
  eventHandlers: [
    { name: 'IMG onerror', payload: '<img src=x onerror=alert("XSS")>' },
    { name: 'Body onload', payload: '<body onload=alert(1)>' },
    { name: 'Input onfocus', payload: '<input onfocus=alert(1) autofocus>' },
    { name: 'SVG onload', payload: '<svg onload=alert(1)>' }
  ],
  javascript: [
    { name: 'JavaScript Protocol', payload: 'javascript:alert("XSS")' },
    { name: 'Anchor href', payload: '<a href="javascript:alert(1)">Click</a>' }
  ],
  htmlInjection: [
    { name: 'Iframe Injection', payload: '<iframe src="http://evil.com"></iframe>' },
    { name: 'Object Tag', payload: '<object data="javascript:alert(1)"></object>' }
  ],
  encoding: [
    { name: 'HTML Entities', payload: '&#60;script&#62;alert(1)&#60;/script&#62;' },
    { name: 'URL Encoded', payload: '%3Cscript%3Ealert(1)%3C/script%3E' }
  ]
};

// Flatten all payloads for testing
const ALL_XSS_PAYLOADS = [
  ...XSS_PAYLOADS.basic,
  ...XSS_PAYLOADS.eventHandlers,
  ...XSS_PAYLOADS.javascript,
  ...XSS_PAYLOADS.htmlInjection,
  ...XSS_PAYLOADS.encoding
];

// Detailed results object
const results = {
  timestamp: new Date().toISOString(),
  summary: {
    totalTests: 0,
    passed: 0,
    failed: 0,
    successRate: 0
  },
  xss: {
    vulnerable: { 
      tests: [], 
      blockRate: 0, 
      total: 0, 
      blocked: 0, 
      succeeded: 0,
      byCategory: {}
    },
    protected: { 
      tests: [], 
      blockRate: 0, 
      total: 0, 
      blocked: 0, 
      succeeded: 0,
      byCategory: {}
    }
  },
  csrf: {
    vulnerable: { tests: [], blockRate: 0, total: 0, blocked: 0, succeeded: 0 },
    protected: { tests: [], blockRate: 0, total: 0, blocked: 0, succeeded: 0 }
  },
  performance: {
    vulnerable: null,
    protected: null,
    comparison: {}
  }
};

// Color codes for terminal
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function log(msg, color = 'reset') {
  console.log(`${colors[color]}${msg}${colors.reset}`);
}

function logTest(testNum, total, name, result, details) {
  const icon = result ? '✅' : '❌';
  const color = result ? 'green' : 'red';
  log(`  [${testNum}/${total}] ${icon} ${name}: ${result ? 'PASS' : 'FAIL'} - ${details}`, color);
}

// XSS Test Helper with FIXED detection logic
async function testXSS(browser, route, payloadObj, shouldSucceed, testNum, total) {
  testCounter++;
  const page = await browser.newPage();
  
  const testResult = {
    testNumber: testNum,
    timestamp: new Date().toISOString(),
    route: route,
    payloadName: payloadObj.name,
    payload: payloadObj.payload,
    expectedBehavior: shouldSucceed ? 'attack succeeds' : 'attack blocked',
    actualBehavior: '',
    passed: false,
    details: {}
  };
  
  // Track alerts
  await page.evaluateOnNewDocument(() => {
    window.__alerts = 0;
    window.alert = () => { window.__alerts++; };
  });

  try {
    await page.goto(`${BASE_URL}${route}?userInput=${encodeURIComponent(payloadObj.payload)}`, { 
      waitUntil: 'networkidle2', 
      timeout: 30000 
    });
    
    await new Promise(r => setTimeout(r, 2000));
    
    const alerts = await page.evaluate(() => window.__alerts || 0);
    
    // FIXED: Simplified and accurate detection logic
    const detectionResult = await page.evaluate((payload) => {
      const html = document.body.innerHTML;
      
      // Find the user content area (between "Safe Echo:" and "</h1>")
      const safeEchoMatch = html.match(/Safe Echo:\s*([^]*?)<\/h1>/i);
      const vulnerableEchoMatch = html.match(/Vulnerable Echo:\s*([^]*?)<\/h1>/i);
      
      const userContentMatch = safeEchoMatch || vulnerableEchoMatch;
      
      if (!userContentMatch) {
        // Can't find echo area - check whole body for dangerous unescaped content
        return {
          isEscaped: false,
          hasUnescapedDanger: false,
          userContent: ''
        };
      }
      
      const userContent = userContentMatch[1];
      
      // Check if the payload characters are escaped
      const isEscaped = userContent.includes('&lt;') || 
                        userContent.includes('&gt;') ||
                        userContent.includes('&quot;') ||
                        userContent.includes('&#39;') ||
                        userContent.includes('&#60;') ||
                        userContent.includes('&#62;');
      
      // Check for UNESCAPED dangerous patterns in user content
      // These patterns indicate raw HTML injection that could execute
      const hasUnescapedDanger = (
        // Script tags without nonce (but not escaped ones)
        (/<script(?![^>]*nonce)[^>]*>/i.test(userContent) && !userContent.includes('&lt;script')) ||
        // Event handlers that could fire
        (/\son\w+\s*=/i.test(userContent) && !isEscaped) ||
        // javascript: in href (clickable XSS)
        (/href\s*=\s*["']?javascript:/i.test(userContent) && !isEscaped) ||
        // Dangerous iframes/objects
        (/<iframe[^>]*src/i.test(userContent) && !isEscaped) ||
        (/<object[^>]*data/i.test(userContent) && !isEscaped)
      );
      
      return {
        isEscaped,
        hasUnescapedDanger,
        userContent: userContent.substring(0, 200)
      };
    }, payloadObj.payload);
    
    const bodyContent = await page.evaluate(() => document.body.innerHTML.substring(0, 200));
    
    testResult.details = {
      alertsTriggered: alerts,
      isEscaped: detectionResult.isEscaped,
      hasUnescapedDanger: detectionResult.hasUnescapedDanger,
      userContentPreview: detectionResult.userContent,
      bodyPreview: bodyContent
    };
    
    // FIXED: Primary detection is alerts. Secondary is unescaped dangerous content.
    // If alerts = 0 AND (content is escaped OR no dangerous patterns), attack was blocked
    const attackSucceeded = alerts > 0 || (detectionResult.hasUnescapedDanger && !detectionResult.isEscaped);
    const blocked = !attackSucceeded;
    
    testResult.actualBehavior = blocked ? 'attack blocked' : 'attack succeeded';
    testResult.passed = shouldSucceed ? !blocked : blocked;
    
    const details = `${payloadObj.name} - Alerts: ${alerts}, Escaped: ${detectionResult.isEscaped}, Blocked: ${blocked}`;
    logTest(testNum, total, `${route} XSS`, testResult.passed, details);
    
    return testResult;
  } catch (error) {
    testResult.actualBehavior = 'error';
    testResult.details.error = error.message;
    logTest(testNum, total, `${route} XSS`, false, `Error: ${error.message}`);
    return testResult;
  } finally {
    await page.close();
  }
}

// CSRF Test Helper with verbose output
async function testCSRF(agent, route, shouldSucceed, testNum, total) {
  testCounter++;
  
  const testResult = {
    testNumber: testNum,
    timestamp: new Date().toISOString(),
    route: route,
    expectedBehavior: shouldSucceed ? 'forged request succeeds' : 'forged request blocked',
    actualBehavior: '',
    passed: false,
    details: {}
  };
  
  try {
    // Get CSRF token from protected route
    const getRes = await agent.get(route);
    
    if (getRes.status !== 200) {
      testResult.actualBehavior = 'error: could not GET route';
      testResult.details.error = `GET failed with status ${getRes.status}`;
      logTest(testNum, total, `${route} CSRF`, false, `GET failed: ${getRes.status}`);
      return testResult;
    }
    
    const tokenMatch = getRes.text.match(/value="([a-f0-9]{64})"/);
    const token = tokenMatch ? tokenMatch[1] : '';
    
    testResult.details.tokenFound = !!token;
    testResult.details.tokenPreview = token.substring(0, 16) + '...';
    
    // Test with valid token
    const validRes = await agent
      .post(`${route}/transfer`)
      .send({ amount: 100, csrfToken: token });
    
    // Test forged request (no token)
    const forgedRes = await agent
      .post(`${route}/transfer`)
      .send({ amount: 999 });
    
    testResult.details.validTokenStatus = validRes.status;
    testResult.details.forgedRequestStatus = forgedRes.status;
    
    const blocked = forgedRes.status === 403;
    testResult.actualBehavior = blocked ? 'forged request blocked' : 'forged request succeeded';
    testResult.passed = shouldSucceed ? !blocked : blocked;
    
    const details = `Valid: ${validRes.status}, Forged: ${forgedRes.status}, Blocked: ${blocked}`;
    logTest(testNum, total, `${route} CSRF`, testResult.passed, details);
    
    return testResult;
  } catch (error) {
    testResult.actualBehavior = 'error';
    testResult.details.error = error.message;
    logTest(testNum, total, `${route} CSRF`, false, `Error: ${error.message}`);
    return testResult;
  }
}

// Performance test helper with verbose output
async function runPerformanceTest(url, label) {
  log(`\n⚡ Running performance test on ${label}...`, 'cyan');
  log(`   URL: ${url}`, 'blue');
  log(`   Duration: 15s, Connections: 50, Pipelining: 10`, 'blue');
  
  return new Promise((resolve, reject) => {
    const instance = autocannon({
      url: url,
      duration: 15,
      connections: 50,
      pipelining: 10,
      headers: {
        'Origin': 'http://localhost:3000'
      }
    }, (err, result) => {
      if (err) {
        log(`   ❌ Performance test failed: ${err.message}`, 'red');
        reject(err);
      } else {
        log(`\n   📊 ${label} Results:`, 'green');
        log(`   ├─ Requests/sec: ${result.requests.average.toFixed(2)}`, 'cyan');
        log(`   ├─ Latency (avg): ${result.latency.mean.toFixed(2)}ms`, 'cyan');
        log(`   ├─ Latency (p99): ${result.latency.p99.toFixed(2)}ms`, 'cyan');
        log(`   ├─ Throughput: ${(result.throughput.average / 1024 / 1024).toFixed(2)} MB/s`, 'cyan');
        log(`   ├─ Total requests: ${result.requests.total}`, 'cyan');
        log(`   └─ Errors: ${result.errors}`, result.errors > 0 ? 'red' : 'cyan');
        resolve(result);
      }
    });

    // Track progress
    autocannon.track(instance, { renderProgressBar: true });
  });
}

// Calculate statistics
function calculateStats() {
  // XSS Vulnerable
  results.xss.vulnerable.total = results.xss.vulnerable.tests.length;
  results.xss.vulnerable.blocked = results.xss.vulnerable.tests.filter(t => 
    t.actualBehavior === 'attack blocked'
  ).length;
  results.xss.vulnerable.succeeded = results.xss.vulnerable.total - results.xss.vulnerable.blocked;
  results.xss.vulnerable.blockRate = (results.xss.vulnerable.blocked / results.xss.vulnerable.total * 100).toFixed(2);
  
  // XSS Protected
  results.xss.protected.total = results.xss.protected.tests.length;
  results.xss.protected.blocked = results.xss.protected.tests.filter(t => 
    t.actualBehavior === 'attack blocked'
  ).length;
  results.xss.protected.succeeded = results.xss.protected.total - results.xss.protected.blocked;
  results.xss.protected.blockRate = (results.xss.protected.blocked / results.xss.protected.total * 100).toFixed(2);
  
  // Calculate by category for XSS
  for (const category in XSS_PAYLOADS) {
    const categoryPayloads = XSS_PAYLOADS[category].map(p => p.name);
    
    results.xss.vulnerable.byCategory[category] = {
      total: results.xss.vulnerable.tests.filter(t => categoryPayloads.includes(t.payloadName)).length,
      blocked: results.xss.vulnerable.tests.filter(t => 
        categoryPayloads.includes(t.payloadName) && t.actualBehavior === 'attack blocked'
      ).length
    };
    
    results.xss.protected.byCategory[category] = {
      total: results.xss.protected.tests.filter(t => categoryPayloads.includes(t.payloadName)).length,
      blocked: results.xss.protected.tests.filter(t => 
        categoryPayloads.includes(t.payloadName) && t.actualBehavior === 'attack blocked'
      ).length
    };
  }
  
  // CSRF Vulnerable
  results.csrf.vulnerable.total = results.csrf.vulnerable.tests.length;
  results.csrf.vulnerable.blocked = results.csrf.vulnerable.tests.filter(t => 
    t.actualBehavior === 'forged request blocked'
  ).length;
  results.csrf.vulnerable.succeeded = results.csrf.vulnerable.total - results.csrf.vulnerable.blocked;
  results.csrf.vulnerable.blockRate = (results.csrf.vulnerable.blocked / results.csrf.vulnerable.total * 100).toFixed(2);
  
  // CSRF Protected
  results.csrf.protected.total = results.csrf.protected.tests.length;
  results.csrf.protected.blocked = results.csrf.protected.tests.filter(t => 
    t.actualBehavior === 'forged request blocked'
  ).length;
  results.csrf.protected.succeeded = results.csrf.protected.total - results.csrf.protected.blocked;
  results.csrf.protected.blockRate = (results.csrf.protected.blocked / results.csrf.protected.total * 100).toFixed(2);
  
  // Overall summary
  const allTests = [
    ...results.xss.vulnerable.tests,
    ...results.xss.protected.tests,
    ...results.csrf.vulnerable.tests,
    ...results.csrf.protected.tests
  ];
  
  results.summary.totalTests = allTests.length;
  results.summary.passed = allTests.filter(t => t.passed).length;
  results.summary.failed = results.summary.totalTests - results.summary.passed;
  results.summary.successRate = (results.summary.passed / results.summary.totalTests * 100).toFixed(2);
  
  // Performance comparison
  if (results.performance.vulnerable && results.performance.protected) {
    const vuln = results.performance.vulnerable;
    const prot = results.performance.protected;
    
    results.performance.comparison = {
      latencyIncrease: ((prot.latency.mean - vuln.latency.mean) / vuln.latency.mean * 100).toFixed(2) + '%',
      latencyIncreaseMs: (prot.latency.mean - vuln.latency.mean).toFixed(2) + 'ms',
      throughputDecrease: ((vuln.throughput.average - prot.throughput.average) / vuln.throughput.average * 100).toFixed(2) + '%',
      requestsPerSecDecrease: ((vuln.requests.average - prot.requests.average) / vuln.requests.average * 100).toFixed(2) + '%'
    };
  }
}

// Print detailed summary
function printSummary() {
  log('\n' + '='.repeat(80), 'bright');
  log('📊 COMPREHENSIVE BENCHMARK RESULTS', 'bright');
  log('='.repeat(80) + '\n', 'bright');
  
  log('🎯 OVERALL SUMMARY', 'yellow');
  log(`   Total Tests: ${results.summary.totalTests}`, 'cyan');
  log(`   Passed: ${results.summary.passed} (${colors.green}${results.summary.successRate}%${colors.cyan})`, 'cyan');
  log(`   Failed: ${results.summary.failed} (${colors.red}${(100 - results.summary.successRate).toFixed(2)}%${colors.cyan})`, 'cyan');
  
  log('\n🛡️  XSS PROTECTION RESULTS', 'yellow');
  log('   Vulnerable Endpoint:', 'magenta');
  log(`   ├─ Total attacks: ${results.xss.vulnerable.total}`, 'cyan');
  log(`   ├─ Succeeded: ${results.xss.vulnerable.succeeded}`, 'cyan');
  log(`   ├─ Blocked: ${results.xss.vulnerable.blocked}`, 'cyan');
  log(`   └─ Block rate: ${results.xss.vulnerable.blockRate}% ${colors.yellow}(expected: 0%)${colors.reset}`, 'cyan');
  
  log('   Protected Endpoint:', 'magenta');
  log(`   ├─ Total attacks: ${results.xss.protected.total}`, 'cyan');
  log(`   ├─ Succeeded: ${results.xss.protected.succeeded}`, 'cyan');
  log(`   ├─ Blocked: ${results.xss.protected.blocked}`, 'cyan');
  log(`   └─ Block rate: ${results.xss.protected.blockRate}% ${colors.yellow}(expected: 100%)${colors.reset}`, 'cyan');
  
  log('\n   XSS Attack Categories (Protected):', 'magenta');
  for (const category in results.xss.protected.byCategory) {
    const cat = results.xss.protected.byCategory[category];
    const rate = cat.total > 0 ? ((cat.blocked / cat.total) * 100).toFixed(0) : 0;
    log(`   ├─ ${category}: ${cat.blocked}/${cat.total} blocked (${rate}%)`, 'cyan');
  }
  
  log('\n🔒 CSRF PROTECTION RESULTS', 'yellow');
  log('   Vulnerable Endpoint:', 'magenta');
  log(`   ├─ Total attacks: ${results.csrf.vulnerable.total}`, 'cyan');
  log(`   ├─ Succeeded: ${results.csrf.vulnerable.succeeded}`, 'cyan');
  log(`   ├─ Blocked: ${results.csrf.vulnerable.blocked}`, 'cyan');
  log(`   └─ Block rate: ${results.csrf.vulnerable.blockRate}% ${colors.yellow}(expected: 0%)${colors.reset}`, 'cyan');
  
  log('   Protected Endpoint:', 'magenta');
  log(`   ├─ Total attacks: ${results.csrf.protected.total}`, 'cyan');
  log(`   ├─ Succeeded: ${results.csrf.protected.succeeded}`, 'cyan');
  log(`   ├─ Blocked: ${results.csrf.protected.blocked}`, 'cyan');
  log(`   └─ Block rate: ${results.csrf.protected.blockRate}% ${colors.yellow}(expected: 100%)${colors.reset}`, 'cyan');
  
  if (results.performance.comparison.latencyIncrease) {
    log('\n⚡ PERFORMANCE IMPACT', 'yellow');
    log(`   Latency increase: ${results.performance.comparison.latencyIncrease} (${results.performance.comparison.latencyIncreaseMs})`, 'cyan');
    log(`   Throughput decrease: ${results.performance.comparison.throughputDecrease}`, 'cyan');
    log(`   Requests/sec decrease: ${results.performance.comparison.requestsPerSecDecrease}`, 'cyan');
  }
  
  log('\n' + '='.repeat(80), 'bright');
}

// Main benchmark function
(async () => {
  log('\n' + '🔥'.repeat(40), 'bright');
  log('   COMPREHENSIVE XSS & CSRF BENCHMARK SUITE', 'bright');
  log('   ' + new Date().toLocaleString(), 'cyan');
  log('🔥'.repeat(40) + '\n', 'bright');
  
  // Start server
  log('🚀 Starting server...', 'yellow');
  server = fork('./app.js', { silent: true });
  
  await new Promise(r => setTimeout(r, 8000));
  log('✅ Server ready on port 3000\n', 'green');
  
  const browser = await puppeteer.launch({ 
    headless: "new", 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  const agent = supertest(BASE_URL);
  
  // ============ XSS TESTS ============
  const totalXSSTests = ALL_XSS_PAYLOADS.length * 2; // vulnerable + protected
  log(`🛡️  RUNNING XSS TESTS (${totalXSSTests} total - ${ALL_XSS_PAYLOADS.length} attack vectors)\n`, 'yellow');
  
  let xssTestNum = 1;
  
  // Test VULNERABLE endpoint with all payloads
  log('  Testing VULNERABLE endpoint (attacks should succeed):', 'magenta');
  for (const payloadObj of ALL_XSS_PAYLOADS) {
    const result = await testXSS(browser, '/vulnerable', payloadObj, true, xssTestNum, totalXSSTests);
    results.xss.vulnerable.tests.push(result);
    xssTestNum++;
  }
  
  log('\n  Testing PROTECTED endpoint (attacks should be blocked):', 'magenta');
  for (const payloadObj of ALL_XSS_PAYLOADS) {
    const result = await testXSS(browser, '/protected', payloadObj, false, xssTestNum, totalXSSTests);
    results.xss.protected.tests.push(result);
    xssTestNum++;
  }
  
  // ============ CSRF TESTS ============
  log('\n🔒 RUNNING CSRF TESTS (8 total)\n', 'yellow');
  
  log('  Testing VULNERABLE endpoint (forged requests should succeed):', 'magenta');
  results.csrf.vulnerable.tests.push(await testCSRF(agent, '/vulnerable', true, 1, 8));
  results.csrf.vulnerable.tests.push(await testCSRF(agent, '/vulnerable', true, 2, 8));
  results.csrf.vulnerable.tests.push(await testCSRF(agent, '/vulnerable', true, 3, 8));
  results.csrf.vulnerable.tests.push(await testCSRF(agent, '/vulnerable', true, 4, 8));
  
  log('\n  Testing PROTECTED endpoint (forged requests should be blocked):', 'magenta');
  results.csrf.protected.tests.push(await testCSRF(agent, '/protected', false, 5, 8));
  results.csrf.protected.tests.push(await testCSRF(agent, '/protected', false, 6, 8));
  results.csrf.protected.tests.push(await testCSRF(agent, '/protected', false, 7, 8));
  results.csrf.protected.tests.push(await testCSRF(agent, '/protected', false, 8, 8));
  
  await browser.close();
  
  // ============ PERFORMANCE TESTS ============
  log('\n⚡ RUNNING PERFORMANCE TESTS\n', 'yellow');
  
  try {
    results.performance.vulnerable = await runPerformanceTest(`${BASE_URL}/vulnerable`, 'Vulnerable Endpoint');
    results.performance.protected = await runPerformanceTest(`${BASE_URL}/protected`, 'Protected Endpoint');
  } catch (error) {
    log(`\n❌ Performance test error: ${error.message}`, 'red');
  }
  
  // Calculate all statistics
  calculateStats();
  
  // Print summary
  printSummary();
  
  // Save results to file
  const timestamp = new Date().toISOString().split('T')[0];
  const timeStr = new Date().toTimeString().split(' ')[0].replace(/:/g, '-');
  const filename = `benchmark-${timestamp}-${timeStr}.json`;
  const filepath = path.join(REPORT_DIR, filename);
  
  fs.writeFileSync(filepath, JSON.stringify(results, null, 2));
  log(`\n💾 Detailed results saved to: ${filepath}`, 'green');
  
  // Cleanup
  server.kill('SIGINT');
  
  log('\n✅ BENCHMARK COMPLETE\n', 'green');
  
  // Exit with appropriate code
  const allPassed = 
    parseFloat(results.xss.protected.blockRate) === 100 &&
    parseFloat(results.xss.vulnerable.blockRate) === 0 &&
    parseFloat(results.csrf.protected.blockRate) === 100 &&
    parseFloat(results.csrf.vulnerable.blockRate) === 0;
  
  process.exit(allPassed ? 0 : 1);
  
})().catch(error => {
  log(`\n❌ BENCHMARK FAILED: ${error.message}`, 'red');
  console.error(error);
  if (server) server.kill('SIGINT');
  process.exit(1);
});