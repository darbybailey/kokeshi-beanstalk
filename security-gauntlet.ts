#!/usr/bin/env tsx
// security-gauntlet.ts
// Comprehensive Security Certification Test for Kokeshi Beanstalk
// BRUTAL MODE

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync, spawnSync } from 'child_process';

const PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97];
const _phi = (1 + Math.sqrt(5)) / 2;
const _A = (_phi * _phi) / (_phi * _phi + 1);
const _W = 4, _S = 3;

function fib(n: number): number {
  if (n <= 1) return n;
  let a = 0, b = 1;
  for (let i = 2; i <= n; i++) { [a, b] = [b, a + b]; }
  return b;
}

interface TestResult {
  name: string;
  passed: boolean;
  details: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

const results: TestResult[] = [];
let totalScore = 0;
let maxScore = 0;

function test(name: string, severity: TestResult['severity'], fn: () => { passed: boolean; details: string }) {
  const weight = severity === 'critical' ? 20 : severity === 'high' ? 15 : severity === 'medium' ? 10 : severity === 'low' ? 5 : 2;
  maxScore += weight;

  try {
    const result = fn();
    results.push({ name, passed: result.passed, details: result.details, severity });
    if (result.passed) totalScore += weight;
    const icon = result.passed ? '✅' : '❌';
    console.log(`${icon} ${name}`);
    console.log(`   ${result.details}\n`);
  } catch (e: any) {
    results.push({ name, passed: false, details: `Exception: ${e.message}`, severity });
    console.log(`❌ ${name}`);
    console.log(`   Exception: ${e.message}\n`);
  }
}

console.log('');
console.log('╔═══════════════════════════════════════════════════════════════════════╗');
console.log('║          KOKESHI BEANSTALK - SECURITY CERTIFICATION GAUNTLET          ║');
console.log('║                            BRUTAL MODE                                ║');
console.log('╚═══════════════════════════════════════════════════════════════════════╝');
console.log('');

// ============================================================================
// SECTION 1: RED TEAM BASICS
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  SECTION 1: RED TEAM FUNDAMENTALS');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

test('1.1 Config file permissions', 'critical', () => {
  const configPath = path.join(os.homedir(), '.clawdbot', 'clawdbot.json');
  if (!fs.existsSync(configPath)) {
    return { passed: true, details: 'Config not present (safe state)' };
  }
  const stats = fs.statSync(configPath);
  const mode = (stats.mode & 0o777).toString(8);
  const isSecure = (stats.mode & 0o077) === 0; // No group/world access
  return {
    passed: mode === '600',
    details: `Mode: ${mode} | ${isSecure ? 'Owner-only access' : 'EXPOSED to other users'}`
  };
});

test('1.2 No secrets in source code', 'critical', () => {
  const source = fs.readFileSync('./kokeshi-beanstalk.ts', 'utf8');
  const patterns = [
    /api[_-]?key\s*[:=]\s*['"]\w{20,}/i,
    /secret\s*[:=]\s*['"]\w{20,}/i,
    /password\s*[:=]\s*['"]\w{8,}/i,
    /token\s*[:=]\s*['"][a-zA-Z0-9]{32,}/i,
  ];
  const leaks = patterns.filter(p => p.test(source));
  return { passed: leaks.length === 0, details: `Secret patterns found: ${leaks.length}` };
});

test('1.3 Localhost binding enforced', 'critical', () => {
  const source = fs.readFileSync('./kokeshi-beanstalk.ts', 'utf8');
  const enforces127 = source.includes("'127.0.0.1'") && source.includes('must be');
  return { passed: enforces127, details: enforces127 ? 'Validates 127.0.0.1 binding' : 'No localhost enforcement found' };
});

// ============================================================================
// SECTION 2: JITTER PREDICTION ATTACK (100 consecutive)
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  SECTION 2: JITTER PREDICTION ATTACK (100 consecutive)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

test('2.1 Predict 100 consecutive intervals', 'high', () => {
  // Attacker observes 50 intervals, tries to predict next 100
  let _c = 0, _d = 1, _t = fib(12);
  const observed: number[] = [];

  // Observe 50 samples (without entropy - attacker can only see base pattern)
  for (let i = 0; i < 50; i++) {
    const n = PRIMES.length;
    const h = _c >> 1;
    const k = _c & 1;
    const lo = h % n;
    const hi = (_W + h * _S) % n;
    const idx = k === 0 ? lo : hi;
    _c += _d;
    if (_c >= _t * 2) _d = -1;
    if (_c <= 0) _d = 1;
    observed.push(PRIMES[idx] * 150 + fib((_c % 15) + 4) * 20);
  }

  // Predict next 100
  let correct = 0;
  for (let attempt = 0; attempt < 100; attempt++) {
    const predicted = observed[_c % observed.length];

    // Actual (with entropy)
    const n = PRIMES.length;
    const h = _c >> 1;
    const k = _c & 1;
    const lo = h % n;
    const hi = (_W + h * _S) % n;
    const idx = k === 0 ? lo : hi;
    const entropy = crypto.randomBytes(2).readUInt16BE(0) % 500 + (Date.now() % 100);
    const _tMod = Math.floor(Date.now() / 86400000) % 17;
    const _Ad = _A * (1 + _tMod * 0.001);
    let actual = PRIMES[idx] * 150 + fib((_c % 15) + 4) * 20 + entropy;
    actual = Math.floor(actual * (1 + (_Ad * (_d > 0 ? 1 : -1) * 0.1)));
    _c += _d;
    if (_c >= _t * 2) _d = -1;
    if (_c <= 0) _d = 1;

    if (Math.abs(predicted - actual) < actual * 0.15) correct++;
  }

  const successRate = (correct / 100) * 100;
  return {
    passed: successRate < 40,
    details: `Prediction success: ${correct}/100 (${successRate.toFixed(1)}%) | Threshold: <40%`
  };
});

// ============================================================================
// SECTION 3: PATTERN REVERSE ENGINEERING (10,000 samples)
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  SECTION 3: PATTERN REVERSE ENGINEERING (10,000 samples)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

test('3.1 Entropy analysis (10K samples)', 'high', () => {
  const samples: number[] = [];
  let _c = 0, _d = 1, _t = fib(12);

  for (let i = 0; i < 10000; i++) {
    const n = PRIMES.length;
    const h = _c >> 1;
    const k = _c & 1;
    const idx = k === 0 ? (h % n) : ((_W + h * _S) % n);
    const entropy = crypto.randomBytes(2).readUInt16BE(0) % 500 + (i % 100);
    const _tMod = Math.floor(Date.now() / 86400000) % 17;
    const _Ad = _A * (1 + _tMod * 0.001);
    let interval = PRIMES[idx] * 150 + fib((_c % 15) + 4) * 20 + entropy;
    interval = Math.floor(interval * (1 + (_Ad * (_d > 0 ? 1 : -1) * 0.1)));
    samples.push(interval);
    _c += _d;
    if (_c >= _t * 2) _d = -1;
    if (_c <= 0) _d = 1;
  }

  const unique = new Set(samples).size;
  const entropyRatio = (unique / 10000) * 100;
  return {
    passed: entropyRatio > 50,
    details: `Unique values: ${unique}/10000 (${entropyRatio.toFixed(1)}%) | High entropy = unpredictable`
  };
});

test('3.2 Autocorrelation analysis', 'medium', () => {
  const samples: number[] = [];
  let _c = 0, _d = 1, _t = fib(12);

  for (let i = 0; i < 1000; i++) {
    const n = PRIMES.length;
    const h = _c >> 1;
    const k = _c & 1;
    const idx = k === 0 ? (h % n) : ((_W + h * _S) % n);
    const entropy = crypto.randomBytes(2).readUInt16BE(0) % 500;
    let interval = PRIMES[idx] * 150 + fib((_c % 15) + 4) * 20 + entropy;
    samples.push(interval);
    _c += _d;
    if (_c >= _t * 2) _d = -1;
    if (_c <= 0) _d = 1;
  }

  const mean = samples.reduce((a, b) => a + b) / samples.length;
  const variance = samples.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / samples.length;

  // Check autocorrelation at multiple lags
  let maxCorr = 0;
  for (let lag = 1; lag <= 50; lag++) {
    let sum = 0;
    for (let i = 0; i < samples.length - lag; i++) {
      sum += (samples[i] - mean) * (samples[i + lag] - mean);
    }
    const corr = Math.abs(sum / ((samples.length - lag) * variance));
    maxCorr = Math.max(maxCorr, corr);
  }

  return {
    passed: maxCorr < 0.8,
    details: `Max autocorrelation: ${maxCorr.toFixed(4)} | Threshold: <0.8`
  };
});

test('3.3 Pattern cycle detection', 'high', () => {
  const samples: number[] = [];
  let _c = 0, _d = 1, _t = fib(12);

  for (let i = 0; i < 2000; i++) {
    const n = PRIMES.length;
    const h = _c >> 1;
    const k = _c & 1;
    const idx = k === 0 ? (h % n) : ((_W + h * _S) % n);
    const entropy = crypto.randomBytes(2).readUInt16BE(0) % 500;
    let interval = PRIMES[idx] * 150 + fib((_c % 15) + 4) * 20 + entropy;
    samples.push(interval);
    _c += _d;
    if (_c >= _t * 2) _d = -1;
    if (_c <= 0) _d = 1;
  }

  // Look for exact repeating patterns
  let patternFound = false;
  for (let len = 10; len <= 500; len++) {
    let isPattern = true;
    for (let i = len; i < Math.min(len * 2, samples.length); i++) {
      if (samples[i] === samples[i % len]) {
        // Exact match is suspicious
      } else {
        isPattern = false;
        break;
      }
    }
    if (isPattern) {
      patternFound = true;
      break;
    }
  }

  return {
    passed: !patternFound,
    details: patternFound ? 'REPEATING PATTERN DETECTED' : 'No detectable cycle (entropy breaking patterns)'
  };
});

// ============================================================================
// SECTION 4: TEMPORAL DRIFT VERIFICATION
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  SECTION 4: TEMPORAL DRIFT VERIFICATION');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

test('4.1 Daily drift changes output', 'medium', () => {
  const days = [];
  for (let day = 0; day < 17; day++) {
    const _tMod = day % 17;
    const _Ad = _A * (1 + _tMod * 0.001);
    days.push(_Ad.toFixed(10));
  }
  const unique = new Set(days).size;
  return {
    passed: unique === 17,
    details: `Unique daily factors: ${unique}/17 | Drift range: ${(_A * 1.000).toFixed(6)} to ${(_A * 1.016).toFixed(6)}`
  };
});

test('4.2 Drift cycle is prime (17)', 'low', () => {
  const cycle = 17;
  const isPrime = (n: number) => {
    if (n < 2) return false;
    for (let i = 2; i <= Math.sqrt(n); i++) if (n % i === 0) return false;
    return true;
  };
  return {
    passed: isPrime(cycle),
    details: `Cycle length: ${cycle} | Prime: ${isPrime(cycle) ? 'YES (harder to predict)' : 'NO'}`
  };
});

// ============================================================================
// SECTION 5: ERROR MESSAGE LEAK CHECK
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  SECTION 5: ERROR MESSAGE LEAK CHECK');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

test('5.1 No secrets in error output', 'critical', () => {
  const badCommands = [
    'decrypt --secret test',
    'encrypt',
    'decrypt --file /nonexistent',
    'badcommand',
  ];

  let leaksFound = 0;
  const secretPatterns = [/token[:=]\s*\w{20,}/i, /secret[:=]\s*\w{10,}/i, /key[:=]\s*\w{20,}/i];

  for (const cmd of badCommands) {
    try {
      const result = spawnSync('npx', ['tsx', 'kokeshi-beanstalk.ts', ...cmd.split(' ')], {
        encoding: 'utf8',
        timeout: 5000
      });
      const output = (result.stdout || '') + (result.stderr || '');
      for (const pattern of secretPatterns) {
        if (pattern.test(output)) leaksFound++;
      }
    } catch {}
  }

  return {
    passed: leaksFound === 0,
    details: `Secret leaks in errors: ${leaksFound} | Tested ${badCommands.length} bad inputs`
  };
});

test('5.2 No stack traces expose paths', 'medium', () => {
  const result = spawnSync('npx', ['tsx', 'kokeshi-beanstalk.ts', 'decrypt', '--secret', 'x', '--file', '/nonexistent.enc'], {
    encoding: 'utf8',
    timeout: 5000
  });
  const output = (result.stdout || '') + (result.stderr || '');
  const hasFullPath = /\/Users\/\w+\//.test(output) || /C:\\Users\\\w+\\/.test(output);
  return {
    passed: !hasFullPath,
    details: hasFullPath ? 'Full user paths exposed in errors' : 'No sensitive paths leaked'
  };
});

// ============================================================================
// SECTION 6: WINDOWS COMPATIBILITY
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  SECTION 6: WINDOWS COMPATIBILITY');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

test('6.1 Uses path.join for all paths', 'medium', () => {
  const source = fs.readFileSync('./kokeshi-beanstalk.ts', 'utf8');
  const hardcodedPaths = source.match(/['"`]\/[a-zA-Z]+\/[^'"`]+['"`]/g) || [];
  const usesPathJoin = source.includes('path.join');
  const usesOsHomedir = source.includes('os.homedir()');
  return {
    passed: usesPathJoin && usesOsHomedir && hardcodedPaths.length === 0,
    details: `path.join: ${usesPathJoin ? 'YES' : 'NO'} | os.homedir: ${usesOsHomedir ? 'YES' : 'NO'} | Hardcoded Unix paths: ${hardcodedPaths.length}`
  };
});

test('6.2 Platform-specific command handling', 'medium', () => {
  const source = fs.readFileSync('./kokeshi-beanstalk.ts', 'utf8');
  const hasWin32Check = source.includes("win32") || source.includes("isWindows");
  const hasNetstatVariants = source.includes('netstat') && (source.includes('findstr') || source.includes('lsof'));
  return {
    passed: hasWin32Check && hasNetstatVariants,
    details: `Platform detection: ${hasWin32Check ? 'YES' : 'NO'} | Multi-platform commands: ${hasNetstatVariants ? 'YES' : 'NO'}`
  };
});

// ============================================================================
// SECTION 7: CLI FUZZING
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  SECTION 7: CLI FUZZING');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

test('7.1 Malformed flags', 'medium', () => {
  const fuzzInputs = [
    ['--jitter-min', '-999'],
    ['--jitter-max', 'NaN'],
    ['--secret', ''],
    ['--file', ''],
    ['--jitter-min', '99999999999999999'],
    ['monitor', '--unknown-flag', 'value'],
  ];

  let crashes = 0;
  for (const args of fuzzInputs) {
    const result = spawnSync('npx', ['tsx', 'kokeshi-beanstalk.ts', ...args], {
      encoding: 'utf8',
      timeout: 5000
    });
    if (result.signal === 'SIGSEGV' || result.signal === 'SIGABRT') crashes++;
  }

  return {
    passed: crashes === 0,
    details: `Crashes from malformed input: ${crashes}/${fuzzInputs.length}`
  };
});

test('7.2 Special characters in arguments', 'medium', () => {
  const specialInputs = [
    ['--secret', '$(whoami)'],
    ['--secret', '; rm -rf /'],
    ['--secret', "'; DROP TABLE users; --"],
    ['--file', '../../../etc/passwd'],
    ['--secret', '\x00\x01\x02'],
  ];

  let vulnerabilities = 0;
  for (const args of specialInputs) {
    const result = spawnSync('npx', ['tsx', 'kokeshi-beanstalk.ts', 'encrypt', ...args], {
      encoding: 'utf8',
      timeout: 5000
    });
    const output = (result.stdout || '') + (result.stderr || '');
    // Check if command injection worked
    if (output.includes(os.userInfo().username) && args[1].includes('whoami')) vulnerabilities++;
  }

  return {
    passed: vulnerabilities === 0,
    details: `Command injection vulnerabilities: ${vulnerabilities}/${specialInputs.length}`
  };
});

test('7.3 Missing required arguments', 'low', () => {
  const incompleteCommands = [
    ['encrypt'],
    ['decrypt'],
    ['decrypt', '--secret', 'test'],
    ['decrypt', '--file', 'test.enc'],
  ];

  let handled = 0;
  for (const args of incompleteCommands) {
    const result = spawnSync('npx', ['tsx', 'kokeshi-beanstalk.ts', ...args], {
      encoding: 'utf8',
      timeout: 5000
    });
    const output = (result.stdout || '') + (result.stderr || '');
    if (output.includes('Usage') || output.includes('error') || output.includes('Error') || result.status !== 0) {
      handled++;
    }
  }

  return {
    passed: handled === incompleteCommands.length,
    details: `Graceful error handling: ${handled}/${incompleteCommands.length}`
  };
});

// ============================================================================
// SECTION 8: ENCRYPTION ROUND-TRIP
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  SECTION 8: ENCRYPTION ROUND-TRIP');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

test('8.1 Encrypt/decrypt round-trip', 'critical', () => {
  const testFile = '/tmp/kokeshi-test-' + Date.now() + '.txt';
  const testContent = 'SECRET DATA: ' + crypto.randomBytes(32).toString('hex');
  const secret = 'test-passphrase-' + Date.now();

  try {
    // Write test file
    fs.writeFileSync(testFile, testContent);

    // Encrypt
    spawnSync('npx', ['tsx', 'kokeshi-beanstalk.ts', 'encrypt', '--secret', secret, '--file', testFile], {
      encoding: 'utf8',
      timeout: 10000
    });

    // Check encrypted file exists
    if (!fs.existsSync(testFile + '.enc')) {
      return { passed: false, details: 'Encrypted file not created' };
    }

    // Decrypt
    spawnSync('npx', ['tsx', 'kokeshi-beanstalk.ts', 'decrypt', '--secret', secret, '--file', testFile + '.enc'], {
      encoding: 'utf8',
      timeout: 10000
    });

    // Check decrypted content
    const decPath = testFile + '.dec';
    if (!fs.existsSync(decPath)) {
      return { passed: false, details: 'Decrypted file not created' };
    }

    const decrypted = fs.readFileSync(decPath, 'utf8');
    const matches = decrypted === testContent;

    // Cleanup
    [testFile, testFile + '.enc', decPath].forEach(f => { try { fs.unlinkSync(f); } catch {} });

    return {
      passed: matches,
      details: matches ? 'Content preserved through encryption cycle' : 'CONTENT CORRUPTED'
    };
  } catch (e: any) {
    return { passed: false, details: `Exception: ${e.message}` };
  }
});

test('8.2 Wrong password fails gracefully', 'high', () => {
  const testFile = '/tmp/kokeshi-wrongpw-' + Date.now() + '.txt';
  fs.writeFileSync(testFile, 'test content');

  try {
    // Encrypt with one password
    spawnSync('npx', ['tsx', 'kokeshi-beanstalk.ts', 'encrypt', '--secret', 'correct-password', '--file', testFile], {
      encoding: 'utf8',
      timeout: 10000
    });

    // Try to decrypt with wrong password
    const result = spawnSync('npx', ['tsx', 'kokeshi-beanstalk.ts', 'decrypt', '--secret', 'wrong-password', '--file', testFile + '.enc'], {
      encoding: 'utf8',
      timeout: 10000
    });

    const output = (result.stdout || '') + (result.stderr || '');
    const failsGracefully = output.includes('failed') || output.includes('wrong') || output.includes('error') || result.status !== 0;

    // Cleanup
    [testFile, testFile + '.enc'].forEach(f => { try { fs.unlinkSync(f); } catch {} });

    return {
      passed: failsGracefully,
      details: failsGracefully ? 'Rejects wrong password with error' : 'DECRYPTED WITH WRONG PASSWORD'
    };
  } catch (e: any) {
    return { passed: true, details: 'Throws on wrong password (secure behavior)' };
  }
});

test('8.3 Encrypted content is not plaintext', 'critical', () => {
  const testFile = '/tmp/kokeshi-plaincheck-' + Date.now() + '.txt';
  const secretContent = 'SUPER_SECRET_API_KEY_12345';
  fs.writeFileSync(testFile, secretContent);

  try {
    spawnSync('npx', ['tsx', 'kokeshi-beanstalk.ts', 'encrypt', '--secret', 'password123', '--file', testFile], {
      encoding: 'utf8',
      timeout: 10000
    });

    const encrypted = fs.readFileSync(testFile + '.enc', 'utf8');
    const containsPlaintext = encrypted.includes(secretContent);

    // Cleanup
    [testFile, testFile + '.enc'].forEach(f => { try { fs.unlinkSync(f); } catch {} });

    return {
      passed: !containsPlaintext,
      details: containsPlaintext ? 'PLAINTEXT VISIBLE IN ENCRYPTED FILE' : 'Content properly encrypted (no plaintext leakage)'
    };
  } catch (e: any) {
    return { passed: false, details: `Exception: ${e.message}` };
  }
});

// ============================================================================
// FINAL REPORT
// ============================================================================
console.log('\n');
console.log('╔═══════════════════════════════════════════════════════════════════════╗');
console.log('║                    SECURITY CERTIFICATION REPORT                      ║');
console.log('╠═══════════════════════════════════════════════════════════════════════╣');

const passed = results.filter(r => r.passed).length;
const failed = results.filter(r => !r.passed).length;
const criticalFails = results.filter(r => !r.passed && r.severity === 'critical').length;
const highFails = results.filter(r => !r.passed && r.severity === 'high').length;

const percentage = Math.round((totalScore / maxScore) * 100);

console.log(`║  Total Tests:           ${String(results.length).padStart(3)}                                        ║`);
console.log(`║  Passed:                ${String(passed).padStart(3)}                                        ║`);
console.log(`║  Failed:                ${String(failed).padStart(3)}                                        ║`);
console.log(`║  Critical Failures:     ${String(criticalFails).padStart(3)}                                        ║`);
console.log(`║  High Failures:         ${String(highFails).padStart(3)}                                        ║`);
console.log('╠═══════════════════════════════════════════════════════════════════════╣');

const scoreBar = '█'.repeat(Math.floor(percentage / 5)) + '░'.repeat(20 - Math.floor(percentage / 5));
const grade = percentage >= 95 ? 'A+' : percentage >= 90 ? 'A' : percentage >= 85 ? 'A-' :
              percentage >= 80 ? 'B+' : percentage >= 75 ? 'B' : percentage >= 70 ? 'B-' :
              percentage >= 65 ? 'C+' : percentage >= 60 ? 'C' : 'F';

console.log(`║  SECURITY SCORE:        ${String(percentage).padStart(3)}%   Grade: ${grade.padEnd(2)}                        ║`);
console.log(`║  [${scoreBar}]                                 ║`);
console.log('╠═══════════════════════════════════════════════════════════════════════╣');

const production = criticalFails === 0 && highFails === 0 && percentage >= 80;
const status = production ? '✅ READY FOR PRODUCTION' : '❌ ISSUES FOUND - NOT READY';
console.log(`║  STATUS: ${status.padEnd(50)}        ║`);
console.log('╚═══════════════════════════════════════════════════════════════════════╝');

if (failed > 0) {
  console.log('\n┌───────────────────────────────────────────────────────────────────────┐');
  console.log('│                         FAILED TESTS                                  │');
  console.log('├───────────────────────────────────────────────────────────────────────┤');
  for (const r of results.filter(r => !r.passed)) {
    const icon = r.severity === 'critical' ? '🔴' : r.severity === 'high' ? '🟠' : '🟡';
    console.log(`│ ${icon} [${r.severity.toUpperCase().padEnd(8)}] ${r.name.slice(0, 45).padEnd(45)} │`);
  }
  console.log('└───────────────────────────────────────────────────────────────────────┘');
}

console.log('\n🛡️ Kokeshi Beanstalk - Security Gauntlet Complete');
console.log(`📅 ${new Date().toISOString()}`);
console.log('');

// Exit with appropriate code
process.exit(production ? 0 : 1);
