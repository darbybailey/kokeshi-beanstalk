#!/usr/bin/env tsx
// kokeshi-beanstalk.ts
// Runtime Guardian for Clawdbot
// A Darby Tool from PIP Projects Inc.
// Prime-Fibonacci jitter timing + Bloom filter + Config validation
// MIT License - PIP Projects Inc.

import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto, { scryptSync, createCipheriv, createDecipheriv } from 'crypto';
import { execSync } from 'child_process';

// ---------- Constants ----------
const CLAWDBOT_CONFIG_PATH = path.join(os.homedir(), '.clawdbot', 'clawdbot.json');
const CLAWD_WORKSPACE = path.join(os.homedir(), 'clawd');
const BLOOM_STATE_PATH = path.join(os.homedir(), '.clawdbot', 'beanstalk-bloom.json');
const GATEWAY_PORT = 18789;

const PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97];

// Fibonacci generator
function fib(n: number): number {
  if (n <= 1) return n;
  let a = 0, b = 1;
  for (let i = 2; i <= n; i++) {
    [a, b] = [b, a + b];
  }
  return b;
}

// ---------- Fibonacci Bloom Filter ----------
class FibonacciBloomFilter {
  private size: number;
  private bits: Uint8Array;
  private hashCount: number = 5;

  constructor(expectedItems: number = 1000, falsePositiveRate: number = 0.01) {
    const m = -(expectedItems * Math.log(falsePositiveRate)) / (Math.log(2) ** 2);
    this.size = this.nearestFib(Math.ceil(m));
    this.bits = new Uint8Array(Math.ceil(this.size / 8));
  }

  private nearestFib(target: number): number {
    let a = 0, b = 1;
    while (b < target) {
      [a, b] = [b, a + b];
    }
    return b;
  }

  private hashes(item: string): number[] {
    const offsets: number[] = [];
    for (let i = 0; i < this.hashCount; i++) {
      offsets.push(fib(i + 5));
    }
    const hash1 = crypto.createHash('sha256').update(item + 'salt1').digest();
    const hash2 = crypto.createHash('sha256').update(item + 'salt2').digest();
    return offsets.map((offset, i) => {
      const h = (BigInt('0x' + hash1.slice(i * 4, (i + 1) * 4).toString('hex')) +
                 BigInt('0x' + hash2.slice(i * 4, (i + 1) * 4).toString('hex')) +
                 BigInt(offset)) % BigInt(this.size);
      return Number(h);
    });
  }

  add(item: string): void {
    for (const idx of this.hashes(item)) {
      this.bits[Math.floor(idx / 8)] |= 1 << (idx % 8);
    }
  }

  mightContain(item: string): boolean {
    return this.hashes(item).every(idx => 
      (this.bits[Math.floor(idx / 8)] & (1 << (idx % 8))) !== 0
    );
  }

  save(): void {
    fs.writeFileSync(BLOOM_STATE_PATH, JSON.stringify({ size: this.size, bits: Array.from(this.bits) }));
  }

  static load(): FibonacciBloomFilter | null {
    if (!fs.existsSync(BLOOM_STATE_PATH)) return null;
    try {
      const data = JSON.parse(fs.readFileSync(BLOOM_STATE_PATH, 'utf8'));
      const filter = new FibonacciBloomFilter();
      filter.size = data.size;
      filter.bits = Uint8Array.from(data.bits);
      return filter;
    } catch {
      return null;
    }
  }
}

// ---------- Encryption Utilities ----------
class SoulEncryption {
  private static ALGORITHM = 'aes-256-cbc';

  static encrypt(content: string, secret: string): string {
    const salt = crypto.randomBytes(16);
    const key = scryptSync(secret, salt, 32);
    const iv = crypto.randomBytes(16);
    const cipher = createCipheriv(this.ALGORITHM, key, iv);
    let encrypted = cipher.update(content, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${salt.toString('hex')}:${iv.toString('hex')}:${encrypted}`;
  }

  static decrypt(encryptedData: string, secret: string): string {
    const [saltHex, ivHex, encrypted] = encryptedData.split(':');
    const salt = Buffer.from(saltHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const key = scryptSync(secret, salt, 32);
    const decipher = createDecipheriv(this.ALGORITHM, key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  static encryptFile(filePath: string, secret: string): void {
    if (!fs.existsSync(filePath)) {
      console.error(`File not found: ${filePath}`);
      return;
    }
    const content = fs.readFileSync(filePath, 'utf8');
    const encrypted = this.encrypt(content, secret);
    fs.writeFileSync(filePath + '.enc', encrypted);
    console.log(`Encrypted: ${filePath} -> ${filePath}.enc`);
  }

  static decryptFile(encryptedPath: string, secret: string, outputPath?: string): void {
    if (!fs.existsSync(encryptedPath)) {
      console.error(`File not found: ${encryptedPath}`);
      return;
    }
    const encrypted = fs.readFileSync(encryptedPath, 'utf8');
    try {
      const decrypted = this.decrypt(encrypted, secret);
      const output = outputPath || encryptedPath.replace('.enc', '.dec');
      fs.writeFileSync(output, decrypted);
      console.log(`Decrypted: ${encryptedPath} -> ${output}`);
    } catch (e) {
      console.error('Decryption failed - wrong secret or corrupted file');
    }
  }
}

// ---------- Hardened Config Template ----------
const HARDENED_CONFIG = {
  gateway: {
    bind: '127.0.0.1',
    port: GATEWAY_PORT,
    auth: {
      mode: 'token',
      token: crypto.randomBytes(32).toString('hex'),
    },
    tailscale: { mode: 'off' },
  },
  channels: {
    dmPolicy: 'pairing',
  },
  agents: {
    defaults: {
      sandbox: { mode: 'all' },
      workspace: CLAWD_WORKSPACE,
    },
  },
  security: {
    logging: 'full',
    autoAudit: true,
  },
};

// ---------- Types ----------
interface JitterConfig {
  minMs: number;
  maxMs: number;
  primeMultiplier: number;
  fibMultiplier: number;
}

interface ValidationResult {
  valid: boolean;
  warnings: string[];
  errors: string[];
}

// ---------- Core Class ----------
class KokeshiBeanstalk {
  private primeIdx = 0;
  private bloom: FibonacciBloomFilter;
  private jitterConfig: JitterConfig;
  private isWindows: boolean;

  constructor(jitterConfig: Partial<JitterConfig> = {}) {
    this.bloom = FibonacciBloomFilter.load() || new FibonacciBloomFilter();
    this.isWindows = os.platform() === 'win32';
    this.jitterConfig = {
      minMs: jitterConfig.minMs ?? 500,
      maxMs: jitterConfig.maxMs ?? 15000,
      primeMultiplier: jitterConfig.primeMultiplier ?? 150,
      fibMultiplier: jitterConfig.fibMultiplier ?? 20,
    };
  }

  nextJitterMs(): number {
    const primeBase = PRIMES[this.primeIdx % PRIMES.length];
    const fibVariation = fib((this.primeIdx % 15) + 4);
    this.primeIdx++;

    let interval = primeBase * this.jitterConfig.primeMultiplier + fibVariation * this.jitterConfig.fibMultiplier;
    interval = Math.max(interval, this.jitterConfig.minMs);
    interval = Math.min(interval, this.jitterConfig.maxMs);
    return interval;
  }

  private validateConfig(config: any): ValidationResult {
    const result: ValidationResult = { valid: true, warnings: [], errors: [] };

    if (config.gateway?.bind && config.gateway.bind !== '127.0.0.1') {
      result.errors.push(`Gateway bind is '${config.gateway.bind}' - must be '127.0.0.1'`);
    }
    if (config.gateway?.auth?.mode !== 'token') {
      result.errors.push(`Gateway auth mode is not 'token' - insecure`);
    }
    if (!config.gateway?.auth?.token && !process.env.CLAWDBOT_AUTH_TOKEN) {
      result.errors.push(`No gateway auth token configured`);
    }

    if (config.channels?.dmPolicy !== 'pairing') {
      result.warnings.push(`dmPolicy is not 'pairing'`);
    }
    if (config.agents?.defaults?.sandbox?.mode !== 'all') {
      result.warnings.push(`Sandbox mode is not 'all'`);
    }
    if (config.gateway?.tailscale?.mode !== 'off') {
      result.warnings.push(`Tailscale mode is not 'off'`);
    }

    if (result.errors.length > 0) result.valid = false;
    return result;
  }

  hardenConfig(): void {
    if (!fs.existsSync(path.dirname(CLAWDBOT_CONFIG_PATH))) {
      fs.mkdirSync(path.dirname(CLAWDBOT_CONFIG_PATH), { recursive: true });
    }

    let config: any = {};
    let existing = false;
    if (fs.existsSync(CLAWDBOT_CONFIG_PATH)) {
      config = JSON.parse(fs.readFileSync(CLAWDBOT_CONFIG_PATH, 'utf8'));
      existing = true;
      console.log('Existing config found - merging');
    }

    const merged = { ...HARDENED_CONFIG, ...config };
    fs.writeFileSync(CLAWDBOT_CONFIG_PATH, JSON.stringify(merged, null, 2));

    const validation = this.validateConfig(merged);
    console.log(`Config ${existing ? 'updated' : 'created'} at ${CLAWDBOT_CONFIG_PATH}`);

    if (!validation.valid) {
      console.error('Critical issues:');
      validation.errors.forEach(e => console.error(`  - ${e}`));
    } else {
      console.log('Config passes validation');
    }

    if (validation.warnings.length > 0) {
      console.warn('Recommendations:');
      validation.warnings.forEach(w => console.warn(`  - ${w}`));
    }

    console.log(`Gateway token: ${merged.gateway.auth.token}`);
  }

  audit(): void {
    console.log('Running Kokeshi Beanstalk audit...');

    let config: any = {};
    if (fs.existsSync(CLAWDBOT_CONFIG_PATH)) {
      config = JSON.parse(fs.readFileSync(CLAWDBOT_CONFIG_PATH, 'utf8'));
    }

    const validation = this.validateConfig(config);
    if (!validation.valid) {
      console.error('Critical misconfigurations:');
      validation.errors.forEach(e => console.error(`  - ${e}`));
    } else {
      console.log('Config passes validation');
    }
    if (validation.warnings.length > 0) {
      console.warn('Recommendations:');
      validation.warnings.forEach(w => console.warn(`  - ${w}`));
    }

    this.checkExposure();
    this.logSuspiciousProbes();
    this.bloom.save();
    console.log(`Next audit in ~${this.nextJitterMs()}ms`);
  }

  monitor(): void {
    console.log(`Starting Kokeshi Beanstalk...`);
    console.log(`  Platform: ${this.isWindows ? 'Windows' : 'Unix'}`);
    console.log(`  Jitter: ${this.jitterConfig.minMs}-${this.jitterConfig.maxMs}ms`);

    const loop = () => {
      this.audit();
      const delay = this.nextJitterMs();
      console.log(`Next check in ${delay}ms`);
      setTimeout(loop, delay);
    };
    loop();
  }

  private checkExposure(): void {
    try {
      const cmd = this.isWindows
        ? `netstat -ano | findstr :${GATEWAY_PORT}`
        : `lsof -i :${GATEWAY_PORT} 2>/dev/null || netstat -an | grep ${GATEWAY_PORT}`;
      
      const output = execSync(cmd, { stdio: 'pipe' }).toString();
      
      if (output.includes('0.0.0.0') || output.includes('*.*') || output.includes('*:')) {
        console.warn('Gateway listening on public interface!');
      }
    } catch {}
  }

  private logSuspiciousProbes(): void {
    try {
      const cmd = this.isWindows
        ? `netstat -ano | findstr :${GATEWAY_PORT} | findstr ESTABLISHED`
        : `netstat -an | grep ${GATEWAY_PORT} | grep ESTABLISHED`;
      
      const connections = execSync(cmd, { stdio: 'pipe' }).toString();
      const lines = connections.split('\n').filter(line => 
        line.includes('ESTABLISHED') && !line.includes('127.0.0.1') && !line.includes('::1')
      );
      
      if (lines.length > 0) {
        const fingerprint = crypto.createHash('sha256').update(connections + Date.now()).digest('hex').slice(0, 16);
        const probeKey = `probe:${fingerprint}`;

        if (this.bloom.mightContain(probeKey)) {
          console.warn(`Repeated probe - BEANSTALK-REPEAT-${fingerprint}`);
        } else {
          console.warn(`New probe - BEANSTALK-PROBE-${fingerprint}`);
        }
        this.bloom.add(probeKey);
      }
    } catch {}
  }

  encryptSensitiveFiles(secret: string): void {
    const sensitiveFiles = [
      path.join(CLAWD_WORKSPACE, 'MEMORY.md'),
      path.join(CLAWD_WORKSPACE, 'SOUL.md'),
      path.join(os.homedir(), '.clawdbot', 'clawdbot.json'),
    ];

    console.log('Encrypting sensitive files...');
    for (const file of sensitiveFiles) {
      if (fs.existsSync(file)) {
        SoulEncryption.encryptFile(file, secret);
      } else {
        console.log(`  Skipped: ${file}`);
      }
    }
    console.log('Store your secret securely!');
  }
}

// ---------- CLI ----------
function parseFlags(args: string[]): { 
  command: string; 
  jitter: Partial<JitterConfig>;
  secret?: string;
  file?: string;
} {
  let command = 'help';
  const jitter: Partial<JitterConfig> = {};
  let secret: string | undefined;
  let file: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      if (arg === '--jitter-min' && args[i + 1]) jitter.minMs = parseInt(args[++i]);
      if (arg === '--jitter-max' && args[i + 1]) jitter.maxMs = parseInt(args[++i]);
      if (arg === '--prime-multiplier' && args[i + 1]) jitter.primeMultiplier = parseInt(args[++i]);
      if (arg === '--fib-multiplier' && args[i + 1]) jitter.fibMultiplier = parseInt(args[++i]);
      if (arg === '--secret' && args[i + 1]) secret = args[++i];
      if (arg === '--file' && args[i + 1]) file = args[++i];
    } else if (!command || command === 'help') {
      command = arg;
    }
  }
  return { command, jitter, secret, file };
}

const args = process.argv.slice(2);
const { command, jitter, secret, file } = parseFlags(args);
const beanstalk = new KokeshiBeanstalk(jitter);

switch (command) {
  case 'harden':
    beanstalk.hardenConfig();
    break;
  case 'audit':
    beanstalk.audit();
    break;
  case 'monitor':
    beanstalk.monitor();
    break;
  case 'encrypt':
    if (!secret) {
      console.error('Usage: kokeshi-beanstalk encrypt --secret <passphrase>');
      process.exit(1);
    }
    if (file) {
      SoulEncryption.encryptFile(file, secret);
    } else {
      beanstalk.encryptSensitiveFiles(secret);
    }
    break;
  case 'decrypt':
    if (!secret || !file) {
      console.error('Usage: kokeshi-beanstalk decrypt --secret <passphrase> --file <path.enc>');
      process.exit(1);
    }
    SoulEncryption.decryptFile(file, secret);
    break;
  default:
    console.log(`
Kokeshi Beanstalk - Runtime Guardian for Clawdbot
A Darby Tool from PIP Projects Inc.

Commands:
  harden                              Create/enforce hardened config
  audit                               One-shot security audit
  monitor [options]                   Continuous monitoring
  encrypt --secret <pass> [--file]    Encrypt sensitive files
  decrypt --secret <pass> --file      Decrypt a file

Jitter Options (monitor only):
  --jitter-min <ms>                   Minimum delay (default: 500)
  --jitter-max <ms>                   Maximum delay (default: 15000)
  --prime-multiplier <n>              Prime scaling (default: 150)
  --fib-multiplier <n>                Fibonacci variation (default: 20)

Examples:
  npx kokeshi-beanstalk harden
  npx kokeshi-beanstalk monitor
  npx kokeshi-beanstalk encrypt --secret "my-passphrase"

MIT License - PIP Projects Inc.
github.com/darbybailey/kokeshi-beanstalk
    `);
}
