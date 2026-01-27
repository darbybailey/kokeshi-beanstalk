#!/usr/bin/env tsx
// kokeshi-beanstalk.ts
// Runtime Guardian for Clawdbot
// A Darby Tool from PIP Projects Inc.
// Prime-Fibonacci jitter timing + Bloom filter + Config validation
// MIT License - PIP Projects Inc.
//
// Developed by Darby Bailey McDonough, Ph.D.
// With AI pair programming assistance

import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto, { scryptSync, createCipheriv, createDecipheriv } from 'crypto';
import { execSync } from 'child_process';
import readline from 'readline';

// ---------- Wizard (Interactive UX) ----------
// "Kokeshi Beanstalk never changes system state without explaining
// what will happen, asking permission, and confirming success."

class Wizard {
  private rl: readline.Interface | null = null;

  private getRL(): readline.Interface {
    if (!this.rl) {
      this.rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
      });
    }
    return this.rl;
  }

  async confirm(question: string): Promise<boolean> {
    return new Promise((resolve) => {
      this.getRL().question(`${question} (yes/no): `, (answer) => {
        resolve(answer.toLowerCase() === 'yes' || answer.toLowerCase() === 'y');
      });
    });
  }

  async askSecret(question: string): Promise<string> {
    return new Promise((resolve) => {
      const rl = this.getRL();

      // Disable echo for password input
      if (process.stdin.isTTY) {
        process.stdout.write(`${question}: `);
        const stdin = process.stdin;
        const wasRaw = stdin.isRaw;
        stdin.setRawMode(true);

        let password = '';
        const onData = (char: Buffer) => {
          const c = char.toString();
          if (c === '\n' || c === '\r') {
            stdin.setRawMode(wasRaw || false);
            stdin.removeListener('data', onData);
            process.stdout.write('\n');
            resolve(password);
          } else if (c === '\u0003') { // Ctrl+C
            process.exit(0);
          } else if (c === '\u007F' || c === '\b') { // Backspace
            if (password.length > 0) {
              password = password.slice(0, -1);
              process.stdout.write('\b \b');
            }
          } else {
            password += c;
            process.stdout.write('*');
          }
        };
        stdin.on('data', onData);
      } else {
        // Non-TTY fallback (piped input)
        rl.question(`${question}: `, resolve);
      }
    });
  }

  async selectMode(): Promise<'obfuscate' | 'keychain' | 'passphrase'> {
    console.log('');
    console.log('┌─────────────────────────────────────────────────────────────────────┐');
    console.log('│  Choose Protection Level:                                           │');
    console.log('├─────────────────────────────────────────────────────────────────────┤');
    console.log('│  1. Obfuscate  - Light scramble, always recoverable (no key)        │');
    console.log('│  2. Keychain   - AES-256 encryption, key in system keychain         │');
    console.log('│  3. Passphrase - AES-256 encryption, YOU manage the key (no rescue) │');
    console.log('└─────────────────────────────────────────────────────────────────────┘');
    console.log('');

    return new Promise((resolve) => {
      const ask = () => {
        this.getRL().question('Enter choice (1/2/3): ', (answer) => {
          if (answer === '1') resolve('obfuscate');
          else if (answer === '2') resolve('keychain');
          else if (answer === '3') resolve('passphrase');
          else {
            console.log('Please enter 1, 2, or 3');
            ask();
          }
        });
      };
      ask();
    });
  }

  async requireConfirmation(text: string): Promise<boolean> {
    return new Promise((resolve) => {
      this.getRL().question(`Type "${text}" to confirm: `, (answer) => {
        resolve(answer === text);
      });
    });
  }

  close(): void {
    if (this.rl) {
      this.rl.close();
      this.rl = null;
    }
  }
}

// ---------- Constants ----------
const CLAWDBOT_CONFIG_PATH = path.join(os.homedir(), '.clawdbot', 'clawdbot.json');
const CLAWD_WORKSPACE = path.join(os.homedir(), 'clawd');
const BLOOM_STATE_PATH = path.join(os.homedir(), '.clawdbot', 'beanstalk-bloom.json');
const KEYCHAIN_SERVICE = 'kokeshi-beanstalk';
const KEYCHAIN_ACCOUNT = 'file-protection-key';
const GATEWAY_PORT = 18789;

// Magic header for protected files
const MAGIC_HEADER = 'KBS1';
const FILE_VERSION = '1';

const PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97];

// Timing sequence: PIP Projects Inc. - patent pending
const _phi = (1 + Math.sqrt(5)) / 2;
const _A = (_phi * _phi) / (_phi * _phi + 1);  // amplitude normalization factor
const _W = 4;  // weave offset
const _S = 3;  // stride

// Temporal drift factor
function _Ad(): number {
  const _t = Math.floor(Date.now() / 86400000) % 17;  // daily cycle, prime modulus
  return _A * (1 + _t * 0.001);  // micro-drift
}

// Fibonacci generator
function fib(n: number): number {
  if (n <= 1) return n;
  let a = 0, b = 1;
  for (let i = 2; i <= n; i++) {
    [a, b] = [b, a + b];
  }
  return b;
}

// ---------- Protection Mode Types ----------
type ProtectionMode = 'obfuscate' | 'keychain' | 'passphrase';

interface ProtectionHeader {
  version: string;
  mode: ProtectionMode;
  createdAt: string;
}

// File extension mapping
const MODE_EXTENSIONS: Record<ProtectionMode, string> = {
  obfuscate: '.obf',
  keychain: '.enc',
  passphrase: '.aes',
};

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

// ---------- Keychain Access ----------
class KeychainAccess {
  private static isWindows = os.platform() === 'win32';
  private static isMac = os.platform() === 'darwin';
  private static isLinux = os.platform() === 'linux';

  static async getKey(): Promise<string | null> {
    try {
      if (this.isMac) {
        const result = execSync(
          `security find-generic-password -s "${KEYCHAIN_SERVICE}" -a "${KEYCHAIN_ACCOUNT}" -w 2>/dev/null`,
          { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
        ).trim();
        return result || null;
      } else if (this.isWindows) {
        const ps = `(Get-StoredCredential -Target "${KEYCHAIN_SERVICE}").Password | ConvertFrom-SecureString -AsPlainText`;
        try {
          return execSync(`powershell -Command "${ps}"`, { encoding: 'utf8' }).trim() || null;
        } catch {
          return null;
        }
      } else if (this.isLinux) {
        try {
          return execSync(
            `secret-tool lookup service "${KEYCHAIN_SERVICE}" account "${KEYCHAIN_ACCOUNT}" 2>/dev/null`,
            { encoding: 'utf8' }
          ).trim() || null;
        } catch {
          return null;
        }
      }
    } catch {
      return null;
    }
    return null;
  }

  static async setKey(key: string): Promise<boolean> {
    try {
      if (this.isMac) {
        execSync(
          `security add-generic-password -s "${KEYCHAIN_SERVICE}" -a "${KEYCHAIN_ACCOUNT}" -w "${key}" -U`,
          { stdio: 'pipe' }
        );
        return true;
      } else if (this.isWindows) {
        const ps = `New-StoredCredential -Target "${KEYCHAIN_SERVICE}" -UserName "${KEYCHAIN_ACCOUNT}" -Password "${key}" -Persist LocalMachine`;
        execSync(`powershell -Command "${ps}"`, { stdio: 'pipe' });
        return true;
      } else if (this.isLinux) {
        execSync(
          `echo -n "${key}" | secret-tool store --label="${KEYCHAIN_SERVICE}" service "${KEYCHAIN_SERVICE}" account "${KEYCHAIN_ACCOUNT}"`,
          { stdio: 'pipe' }
        );
        return true;
      }
    } catch (e) {
      return false;
    }
    return false;
  }

  static getInstructions(): string {
    if (this.isMac) {
      return 'macOS Keychain is available. Make sure Keychain Access is unlocked.';
    } else if (this.isWindows) {
      return 'Windows Credential Manager requires the CredentialManager PowerShell module.\nInstall with: Install-Module -Name CredentialManager';
    } else if (this.isLinux) {
      return 'Linux Secret Service requires secret-tool.\nInstall with: sudo apt install libsecret-tools (Debian/Ubuntu)\n             sudo dnf install libsecret (Fedora)';
    }
    return 'Keychain not supported on this platform.';
  }
}

// ---------- File Protection System (AEAD) ----------
class FileProtection {
  private static ALGORITHM_GCM = 'aes-256-gcm';
  private static AUTH_TAG_LENGTH = 16;

  // Build magic header + JSON metadata
  private static buildHeader(mode: ProtectionMode): string {
    const header: ProtectionHeader = {
      version: FILE_VERSION,
      mode,
      createdAt: new Date().toISOString(),
    };
    return `${MAGIC_HEADER}\n${JSON.stringify(header)}\n`;
  }

  // Parse header from protected file
  static parseHeader(data: string): { header: ProtectionHeader; payload: string } | null {
    const lines = data.split('\n');
    if (lines.length < 3 || lines[0] !== MAGIC_HEADER) {
      return null;
    }
    try {
      const header: ProtectionHeader = JSON.parse(lines[1]);
      const payload = lines.slice(2).join('\n');
      return { header, payload };
    } catch {
      return null;
    }
  }

  // Mode 1: Obfuscate (Base64 + scramble - always reversible, NOT encryption)
  static obfuscate(content: string): string {
    const headerStr = this.buildHeader('obfuscate');

    // Base64 encode
    const b64 = Buffer.from(content, 'utf8').toString('base64');

    // Simple byte rotation (reversible)
    const rotated = b64.split('').map((c, i) => {
      const code = c.charCodeAt(0);
      return String.fromCharCode(code ^ (i % 17));  // XOR with position mod prime
    }).join('');

    return headerStr + Buffer.from(rotated, 'utf8').toString('base64');
  }

  static deobfuscate(data: string): string {
    const parsed = this.parseHeader(data);
    if (!parsed || parsed.header.mode !== 'obfuscate') {
      throw new Error('Not a valid obfuscated file');
    }

    const rotated = Buffer.from(parsed.payload, 'base64').toString('utf8');

    // Reverse XOR rotation
    const b64 = rotated.split('').map((c, i) => {
      const code = c.charCodeAt(0);
      return String.fromCharCode(code ^ (i % 17));
    }).join('');

    return Buffer.from(b64, 'base64').toString('utf8');
  }

  // Mode 2: Keychain (AES-256-GCM AEAD, key in system keychain)
  static async encryptKeychain(content: string): Promise<string> {
    let key = await KeychainAccess.getKey();

    if (!key) {
      key = crypto.randomBytes(32).toString('hex');
      const stored = await KeychainAccess.setKey(key);
      if (!stored) {
        throw new Error('Failed to store key in system keychain.\n' + KeychainAccess.getInstructions());
      }
    }

    const headerStr = this.buildHeader('keychain');

    const salt = crypto.randomBytes(16);
    const derivedKey = scryptSync(key, salt, 32, { N: 16384, r: 8, p: 1 });
    const iv = crypto.randomBytes(12);  // GCM uses 12-byte IV
    const cipher = createCipheriv(this.ALGORITHM_GCM, derivedKey, iv) as crypto.CipherGCM;

    let encrypted = cipher.update(content, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    // Format: salt:iv:authTag:ciphertext
    return headerStr + `${salt.toString('hex')}:${iv.toString('hex')}:${authTag}:${encrypted}`;
  }

  static async decryptKeychain(data: string): Promise<string> {
    const parsed = this.parseHeader(data);
    if (!parsed || parsed.header.mode !== 'keychain') {
      throw new Error('Not a valid keychain-encrypted file');
    }

    const key = await KeychainAccess.getKey();
    if (!key) {
      throw new Error('No key found in system keychain. Cannot decrypt.\n' + KeychainAccess.getInstructions());
    }

    const [saltHex, ivHex, authTagHex, encrypted] = parsed.payload.split(':');
    const salt = Buffer.from(saltHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const derivedKey = scryptSync(key, salt, 32, { N: 16384, r: 8, p: 1 });

    const decipher = createDecipheriv(this.ALGORITHM_GCM, derivedKey, iv) as crypto.DecipherGCM;
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  // Mode 3: Passphrase (AES-256-GCM AEAD, user-managed key)
  static encryptPassphrase(content: string, secret: string): string {
    const headerStr = this.buildHeader('passphrase');

    const salt = crypto.randomBytes(16);
    const key = scryptSync(secret, salt, 32, { N: 16384, r: 8, p: 1 });
    const iv = crypto.randomBytes(12);  // GCM uses 12-byte IV
    const cipher = createCipheriv(this.ALGORITHM_GCM, key, iv) as crypto.CipherGCM;

    let encrypted = cipher.update(content, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    // Format: salt:iv:authTag:ciphertext
    return headerStr + `${salt.toString('hex')}:${iv.toString('hex')}:${authTag}:${encrypted}`;
  }

  static decryptPassphrase(data: string, secret: string): string {
    const parsed = this.parseHeader(data);
    if (!parsed || parsed.header.mode !== 'passphrase') {
      throw new Error('Not a valid passphrase-encrypted file');
    }

    const [saltHex, ivHex, authTagHex, encrypted] = parsed.payload.split(':');
    const salt = Buffer.from(saltHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const key = scryptSync(secret, salt, 32, { N: 16384, r: 8, p: 1 });

    const decipher = createDecipheriv(this.ALGORITHM_GCM, key, iv) as crypto.DecipherGCM;
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  // Verify file integrity (AEAD tamper detection)
  static async verifyIntegrity(filePath: string, secret?: string): Promise<{ valid: boolean; error?: string }> {
    if (!fs.existsSync(filePath)) {
      return { valid: false, error: 'File not found' };
    }

    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const parsed = this.parseHeader(content);

      if (!parsed) {
        return { valid: false, error: 'Invalid file format' };
      }

      // Obfuscated files can't be tampered in a way we can detect
      if (parsed.header.mode === 'obfuscate') {
        try {
          this.deobfuscate(content);
          return { valid: true };
        } catch {
          return { valid: false, error: 'Deobfuscation failed' };
        }
      }

      // For AEAD modes, try to verify the auth tag
      if (parsed.header.mode === 'keychain') {
        try {
          await this.decryptKeychain(content);
          return { valid: true };
        } catch (e: any) {
          if (e.message.includes('auth')) {
            return { valid: false, error: 'TAMPERED - authentication tag verification failed' };
          }
          return { valid: false, error: e.message };
        }
      }

      if (parsed.header.mode === 'passphrase') {
        if (!secret) {
          return { valid: true };  // Can't verify without passphrase
        }
        try {
          this.decryptPassphrase(content, secret);
          return { valid: true };
        } catch (e: any) {
          if (e.message.includes('auth') || e.message.includes('Unsupported state')) {
            return { valid: false, error: 'TAMPERED - authentication tag verification failed' };
          }
          return { valid: false, error: 'Wrong passphrase or corrupted file' };
        }
      }

      return { valid: true };
    } catch (e: any) {
      return { valid: false, error: e.message };
    }
  }

  // Get protection status for audit display
  static getProtectionStatus(filePath: string): { status: string; level: string; tampered?: boolean } {
    const ext = path.extname(filePath);

    if (ext === '.obf') {
      return { status: 'OBFUSCATED', level: 'casual viewing protection (NOT encrypted)' };
    } else if (ext === '.enc') {
      return { status: 'KEYCHAIN', level: 'AES-256-GCM, machine-bound' };
    } else if (ext === '.aes') {
      return { status: 'PASSPHRASE', level: 'AES-256-GCM, user-managed key' };
    }

    // Check file permissions
    try {
      const stats = fs.statSync(filePath);
      const mode = (stats.mode & 0o777).toString(8);
      if (mode === '600') {
        return { status: 'NONE', level: 'plaintext (protected by chmod 600)' };
      }
    } catch {}

    return { status: 'NONE', level: 'plaintext (UNPROTECTED)' };
  }
}

// ---------- Legacy Encryption (for backward compatibility) ----------
class SoulEncryption {
  static encryptFile(filePath: string, secret: string): void {
    console.warn('⚠️  DEPRECATION WARNING: "encrypt" is deprecated.');
    console.warn('   Use "protect --mode passphrase --secret <pass>" instead.\n');

    if (!fs.existsSync(filePath)) {
      console.error(`File not found: ${filePath}`);
      return;
    }
    const content = fs.readFileSync(filePath, 'utf8');
    const encrypted = FileProtection.encryptPassphrase(content, secret);
    fs.writeFileSync(filePath + '.aes', encrypted);
    console.log(`Encrypted: ${filePath} -> ${filePath}.aes`);
  }

  static decryptFile(encryptedPath: string, secret: string): void {
    console.warn('⚠️  DEPRECATION WARNING: "decrypt" is deprecated.');
    console.warn('   Use "unprotect --file <path>" instead.\n');

    if (!fs.existsSync(encryptedPath)) {
      console.error(`File not found: ${encryptedPath}`);
      return;
    }
    const encrypted = fs.readFileSync(encryptedPath, 'utf8');
    try {
      const decrypted = FileProtection.decryptPassphrase(encrypted, secret);
      const output = encryptedPath.replace('.aes', '.dec').replace('.enc', '.dec');
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
  private _c = 0;  // cycle position
  private _d = 1;  // direction
  private _t: number;  // traversal depth
  private bloom: FibonacciBloomFilter;
  private jitterConfig: JitterConfig;
  private isWindows: boolean;

  constructor(jitterConfig: Partial<JitterConfig> = {}) {
    this.bloom = FibonacciBloomFilter.load() || new FibonacciBloomFilter();
    this.isWindows = os.platform() === 'win32';
    this._t = fib(12);  // nested depth
    this.jitterConfig = {
      minMs: jitterConfig.minMs ?? 500,
      maxMs: jitterConfig.maxMs ?? 15000,
      primeMultiplier: jitterConfig.primeMultiplier ?? 150,
      fibMultiplier: jitterConfig.fibMultiplier ?? 20,
    };
  }

  // Standard prime lookup with cache optimization
  private _p(): number {
    const n = PRIMES.length;
    const h = this._c >> 1;                    // half-step
    const k = this._c & 1;                     // alternation flag
    const lo = h % n;                          // lower sequence
    const hi = (_W + h * _S) % n;              // offset sequence
    const idx = k === 0 ? lo : hi;             // interleave

    this._c += this._d;
    if (this._c >= this._t * 2) this._d = -1;  // slapback
    if (this._c <= 0) this._d = 1;             // return

    return PRIMES[idx];
  }

  nextJitterMs(): number {
    const primeBase = this._p();
    const fibVariation = fib((this._c % 15) + 4);

    // Add cryptographic entropy to break predictable patterns
    const entropy = crypto.randomBytes(2).readUInt16BE(0) % 500;
    const _e = process.hrtime()[1] % 100;  // nanosecond noise

    let interval = primeBase * this.jitterConfig.primeMultiplier + fibVariation * this.jitterConfig.fibMultiplier + entropy + _e;
    interval = Math.floor(interval * (1 + (_Ad() * (this._d > 0 ? 1 : -1) * 0.1)));
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

  async hardenConfig(skipPrompts: boolean = false): Promise<void> {
    const wizard = new Wizard();

    try {
      // ═══════════════════════════════════════════════════════════════════════
      // STEP 1: EXPLAIN - Show what will change
      // ═══════════════════════════════════════════════════════════════════════
      console.log('');
      console.log('╔═══════════════════════════════════════════════════════════════════════╗');
      console.log('║              KOKESHI BEANSTALK - HARDEN CONFIG                        ║');
      console.log('║                     Step 1 of 3: Review Changes                       ║');
      console.log('╚═══════════════════════════════════════════════════════════════════════╝');
      console.log('');

      const configExists = fs.existsSync(CLAWDBOT_CONFIG_PATH);
      let currentConfig: any = {};

      if (configExists) {
        currentConfig = JSON.parse(fs.readFileSync(CLAWDBOT_CONFIG_PATH, 'utf8'));
        console.log('📄 Existing config found. The following changes will be applied:');
      } else {
        console.log('📄 No config found. A new secure config will be created:');
      }

      console.log('');
      console.log('┌─────────────────────────────────────────────────────────────────────┐');

      // Show what will change
      const changes: string[] = [];

      if (currentConfig.gateway?.bind !== '127.0.0.1') {
        changes.push('  • Bind gateway to 127.0.0.1 (localhost only)');
      }
      if (currentConfig.gateway?.auth?.mode !== 'token') {
        changes.push('  • Enable token authentication');
      }
      if (!currentConfig.gateway?.auth?.token) {
        changes.push('  • Generate new 256-bit auth token');
      }
      if (currentConfig.gateway?.tailscale?.mode !== 'off') {
        changes.push('  • Disable Tailscale exposure');
      }
      if (currentConfig.channels?.dmPolicy !== 'pairing') {
        changes.push('  • Set DM policy to "pairing"');
      }
      if (currentConfig.agents?.defaults?.sandbox?.mode !== 'all') {
        changes.push('  • Enable sandbox mode for all agents');
      }
      changes.push('  • Set file permissions to 600 (owner-only)');

      if (changes.length === 1) {
        console.log('│  ✅ Config is already secure. Only permission check needed.         │');
      } else {
        changes.forEach(c => console.log('│' + c.padEnd(72) + '│'));
      }

      console.log('└─────────────────────────────────────────────────────────────────────┘');
      console.log('');
      console.log(`📁 Config path: ${CLAWDBOT_CONFIG_PATH}`);
      console.log('');

      // ═══════════════════════════════════════════════════════════════════════
      // STEP 2: CONFIRM - Ask permission
      // ═══════════════════════════════════════════════════════════════════════
      if (!skipPrompts) {
        console.log('═══════════════════════════════════════════════════════════════════════');
        console.log('                     Step 2 of 3: Confirm Changes                      ');
        console.log('═══════════════════════════════════════════════════════════════════════');
        console.log('');

        const confirmed = await wizard.confirm('Ready to apply these changes?');
        if (!confirmed) {
          console.log('\n❌ Cancelled. No changes were made.');
          return;
        }
      }

      // ═══════════════════════════════════════════════════════════════════════
      // STEP 3: EXECUTE - Apply changes and confirm success
      // ═══════════════════════════════════════════════════════════════════════
      console.log('');
      console.log('═══════════════════════════════════════════════════════════════════════');
      console.log('                     Step 3 of 3: Applying Changes                      ');
      console.log('═══════════════════════════════════════════════════════════════════════');
      console.log('');

      if (!fs.existsSync(path.dirname(CLAWDBOT_CONFIG_PATH))) {
        fs.mkdirSync(path.dirname(CLAWDBOT_CONFIG_PATH), { recursive: true });
      }

      const merged = { ...HARDENED_CONFIG, ...currentConfig };

      // Ensure critical security settings
      merged.gateway = merged.gateway || {};
      merged.gateway.bind = '127.0.0.1';
      merged.gateway.auth = merged.gateway.auth || {};
      merged.gateway.auth.mode = 'token';
      if (!merged.gateway.auth.token) {
        merged.gateway.auth.token = crypto.randomBytes(32).toString('hex');
      }
      merged.gateway.tailscale = { mode: 'off' };
      merged.channels = merged.channels || {};
      merged.channels.dmPolicy = 'pairing';
      merged.agents = merged.agents || {};
      merged.agents.defaults = merged.agents.defaults || {};
      merged.agents.defaults.sandbox = { mode: 'all' };

      fs.writeFileSync(CLAWDBOT_CONFIG_PATH, JSON.stringify(merged, null, 2));
      fs.chmodSync(CLAWDBOT_CONFIG_PATH, 0o600);

      console.log('✅ Config saved to ' + CLAWDBOT_CONFIG_PATH);
      console.log('✅ Permissions set to 600 (owner-only)');
      console.log('');
      console.log('┌─────────────────────────────────────────────────────────────────────┐');
      console.log('│  🔑 YOUR GATEWAY AUTH TOKEN (save this somewhere safe!)             │');
      console.log('├─────────────────────────────────────────────────────────────────────┤');
      console.log(`│  ${merged.gateway.auth.token}  │`);
      console.log('└─────────────────────────────────────────────────────────────────────┘');
      console.log('');

      if (!skipPrompts) {
        const saved = await wizard.confirm('Have you saved the token above?');
        if (saved) {
          console.log('\n✅ Hardening complete! Your Clawdbot is now secured.');
        } else {
          console.log('\n⚠️  Please save the token before closing this window!');
          console.log('   You can also find it in: ' + CLAWDBOT_CONFIG_PATH);
        }
      } else {
        console.log('✅ Hardening complete (automated mode).');
      }
    } finally {
      wizard.close();
    }
  }

  // Security scan - reports issues without fixing them (read-only)
  async scan(): Promise<void> {
    interface Finding {
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      plain: string;      // User-friendly description
      technical: string;  // Technical details
      fix: string;        // How to fix it
      points: number;     // Points deducted from score
    }

    const findings: Finding[] = [];
    let config: any = {};

    // Check 1: Config file exists
    if (!fs.existsSync(CLAWDBOT_CONFIG_PATH)) {
      findings.push({
        severity: 'CRITICAL',
        plain: 'Your bot has no security configuration',
        technical: 'No clawdbot.json config file found',
        fix: 'npx kokeshi-beanstalk harden',
        points: 25
      });
    } else {
      config = JSON.parse(fs.readFileSync(CLAWDBOT_CONFIG_PATH, 'utf8'));

      // Check 2: Config file permissions
      const stats = fs.statSync(CLAWDBOT_CONFIG_PATH);
      const mode = (stats.mode & 0o777).toString(8);
      if (mode !== '600') {
        findings.push({
          severity: 'HIGH',
          plain: 'Other users on this computer can read your config',
          technical: `Config file has mode ${mode}, should be 600`,
          fix: `chmod 600 "${CLAWDBOT_CONFIG_PATH}"`,
          points: 15
        });
      }

      // Check 3: Gateway binding
      if (config.gateway?.bind && config.gateway.bind !== '127.0.0.1') {
        findings.push({
          severity: 'CRITICAL',
          plain: 'Your bot is visible to the entire internet',
          technical: `Gateway bound to ${config.gateway.bind} instead of 127.0.0.1`,
          fix: `Edit ${CLAWDBOT_CONFIG_PATH}: set "gateway.bind": "127.0.0.1"`,
          points: 30
        });
      }

      // Check 4: Auth mode
      if (config.gateway?.auth?.mode !== 'token') {
        findings.push({
          severity: 'CRITICAL',
          plain: 'Anyone can control your bot without a password',
          technical: `Auth mode is "${config.gateway?.auth?.mode || 'none'}" - no token required`,
          fix: 'npx kokeshi-beanstalk harden',
          points: 30
        });
      }

      // Check 5: Auth token present
      if (!config.gateway?.auth?.token && !process.env.CLAWDBOT_AUTH_TOKEN) {
        findings.push({
          severity: 'CRITICAL',
          plain: 'Your bot has no access password set',
          technical: 'No gateway auth token configured',
          fix: 'npx kokeshi-beanstalk harden',
          points: 25
        });
      }

      // Check 6: DM Policy
      if (config.channels?.dmPolicy !== 'pairing') {
        findings.push({
          severity: 'MEDIUM',
          plain: 'Your bot accepts messages from anyone',
          technical: `DM policy is "${config.channels?.dmPolicy || 'open'}" instead of "pairing"`,
          fix: `Edit ${CLAWDBOT_CONFIG_PATH}: set "channels.dmPolicy": "pairing"`,
          points: 10
        });
      }

      // Check 7: Sandbox mode
      if (config.agents?.defaults?.sandbox?.mode !== 'all') {
        findings.push({
          severity: 'MEDIUM',
          plain: 'Skills can run any code without sandboxing',
          technical: `Sandbox mode is "${config.agents?.defaults?.sandbox?.mode || 'none'}" instead of "all"`,
          fix: `Edit ${CLAWDBOT_CONFIG_PATH}: set "agents.defaults.sandbox.mode": "all"`,
          points: 10
        });
      }

      // Check 8: Tailscale exposure
      if (config.gateway?.tailscale?.mode && config.gateway.tailscale.mode !== 'off') {
        findings.push({
          severity: 'HIGH',
          plain: 'Your bot is exposed on your Tailscale network',
          technical: `Tailscale mode is "${config.gateway.tailscale.mode}" - network exposed`,
          fix: `Edit ${CLAWDBOT_CONFIG_PATH}: set "gateway.tailscale.mode": "off"`,
          points: 15
        });
      }
    }

    // Check 9: Sensitive files unprotected
    const sensitiveFiles = [
      { path: path.join(CLAWD_WORKSPACE, 'MEMORY.md'), name: 'MEMORY.md', desc: 'memories' },
      { path: path.join(CLAWD_WORKSPACE, 'SOUL.md'), name: 'SOUL.md', desc: 'personality' },
    ];

    for (const { path: filePath, name, desc } of sensitiveFiles) {
      if (fs.existsSync(filePath)) {
        const hasObf = fs.existsSync(filePath + '.obf');
        const hasEnc = fs.existsSync(filePath + '.enc');
        const hasAes = fs.existsSync(filePath + '.aes');

        if (!hasObf && !hasEnc && !hasAes) {
          findings.push({
            severity: 'HIGH',
            plain: `Your ${desc} are stored in plain text`,
            technical: `${name} exists unencrypted`,
            fix: `npx kokeshi-beanstalk protect --secure --file "${filePath}"`,
            points: 15
          });
        }
      }
    }

    // Check 10: Port exposure (runtime check)
    try {
      const cmd = this.isWindows
        ? `netstat -ano | findstr :${GATEWAY_PORT}`
        : `lsof -i :${GATEWAY_PORT} 2>/dev/null || netstat -an | grep ${GATEWAY_PORT}`;

      const output = execSync(cmd, { stdio: 'pipe' }).toString();

      if (output.includes('0.0.0.0') || output.includes('*.*') || output.includes('*:')) {
        findings.push({
          severity: 'CRITICAL',
          plain: 'Your bot is actively listening on ALL network interfaces',
          technical: `Port ${GATEWAY_PORT} bound to 0.0.0.0 (publicly accessible right now!)`,
          fix: 'Fix config and restart Clawdbot',
          points: 30
        });
      }
    } catch {}

    // Calculate score
    const totalDeductions = findings.reduce((sum, f) => sum + f.points, 0);
    const score = Math.max(0, 100 - totalDeductions);
    const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';

    // Print header with score
    console.log('');
    console.log('╔═══════════════════════════════════════════════════════════════════════╗');
    console.log('║              KOKESHI BEANSTALK - SECURITY SCAN                        ║');
    console.log('╠═══════════════════════════════════════════════════════════════════════╣');

    const scoreBar = '█'.repeat(Math.floor(score / 5)) + '░'.repeat(20 - Math.floor(score / 5));
    const scoreColor = score >= 80 ? '✅' : score >= 60 ? '⚠️' : '❌';
    console.log(`║  ${scoreColor} Security Score: ${score}/100  Grade: ${grade}                              ║`.slice(0, 76) + '║');
    console.log(`║  [${scoreBar}]                                       ║`.slice(0, 76) + '║');
    console.log('╚═══════════════════════════════════════════════════════════════════════╝');
    console.log('');

    if (findings.length === 0) {
      console.log('✅ No security issues found. Your installation is properly secured.');
      console.log('');
    } else {
      // Group by severity
      const criticals = findings.filter(f => f.severity === 'CRITICAL');
      const highs = findings.filter(f => f.severity === 'HIGH');
      const mediums = findings.filter(f => f.severity === 'MEDIUM');
      const lows = findings.filter(f => f.severity === 'LOW');

      const printFinding = (f: Finding, icon: string) => {
        console.log(`${icon} [${f.severity}] ${f.plain}`);
        console.log(`   Technical: ${f.technical}`);
        console.log(`   Fix: ${f.fix}`);
        console.log('');
      };

      if (criticals.length > 0) {
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        criticals.forEach(f => printFinding(f, '🔴'));
      }

      if (highs.length > 0) {
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        highs.forEach(f => printFinding(f, '🟠'));
      }

      if (mediums.length > 0) {
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        mediums.forEach(f => printFinding(f, '🟡'));
      }

      if (lows.length > 0) {
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        lows.forEach(f => printFinding(f, '🔵'));
      }

      // Severity legend
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log('🔴 CRITICAL = You could be hacked right now');
      console.log('🟠 HIGH     = Fix this today');
      console.log('🟡 MEDIUM   = Recommended improvement');
      console.log('🔵 LOW      = Nice to have');
      console.log('');

      // Auto-fix suggestion
      console.log('───────────────────────────────────────────────────────────────────────');
      console.log("Don't want to fix manually? Run: npx kokeshi-beanstalk harden");
      console.log('───────────────────────────────────────────────────────────────────────');
    }
  }

  async audit(): Promise<void> {
    console.log('Running Kokeshi Beanstalk audit...\n');

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

    // File Protection Status with tamper detection
    console.log('\nFile Protection Status:');
    const sensitiveFiles = [
      path.join(CLAWD_WORKSPACE, 'MEMORY.md'),
      path.join(CLAWD_WORKSPACE, 'MEMORY.md.obf'),
      path.join(CLAWD_WORKSPACE, 'MEMORY.md.enc'),
      path.join(CLAWD_WORKSPACE, 'MEMORY.md.aes'),
      path.join(CLAWD_WORKSPACE, 'SOUL.md'),
      path.join(CLAWD_WORKSPACE, 'SOUL.md.obf'),
      path.join(CLAWD_WORKSPACE, 'SOUL.md.enc'),
      path.join(CLAWD_WORKSPACE, 'SOUL.md.aes'),
      CLAWDBOT_CONFIG_PATH,
    ];

    const foundFiles: string[] = [];
    for (const file of sensitiveFiles) {
      if (fs.existsSync(file)) {
        foundFiles.push(file);
      }
    }

    if (foundFiles.length === 0) {
      console.log('  No sensitive files found');
    } else {
      for (let idx = 0; idx < foundFiles.length; idx++) {
        const file = foundFiles[idx];
        const isLast = idx === foundFiles.length - 1;
        const prefix = isLast ? '└──' : '├──';
        const { status, level } = FileProtection.getProtectionStatus(file);
        const basename = path.basename(file);

        // Check integrity for encrypted files
        let integrityNote = '';
        if (status === 'KEYCHAIN' || status === 'PASSPHRASE') {
          const integrity = await FileProtection.verifyIntegrity(file);
          if (!integrity.valid && integrity.error?.includes('TAMPERED')) {
            integrityNote = ' [TAMPERED]';
          }
        }

        console.log(`  ${prefix} ${basename.padEnd(20)} [${status}]${integrityNote} - ${level}`);
      }
    }

    this.checkExposure();
    this.logSuspiciousProbes();
    this.bloom.save();
    console.log(`\nNext audit in ~${this.nextJitterMs()}ms`);
  }

  monitor(): void {
    console.log(`Starting Kokeshi Beanstalk...`);
    console.log(`  Platform: ${this.isWindows ? 'Windows' : 'Unix'}`);
    console.log(`  Jitter: ${this.jitterConfig.minMs}-${this.jitterConfig.maxMs}ms`);

    const loop = async () => {
      await this.audit();
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

  async protectFiles(mode: ProtectionMode | undefined, secret?: string, file?: string, force?: boolean, skipPrompts?: boolean): Promise<void> {
    const wizard = new Wizard();

    try {
      // ═══════════════════════════════════════════════════════════════════════
      // STEP 1: EXPLAIN - Show what will be protected
      // ═══════════════════════════════════════════════════════════════════════
      console.log('');
      console.log('╔═══════════════════════════════════════════════════════════════════════╗');
      console.log('║              KOKESHI BEANSTALK - PROTECT FILES                        ║');
      console.log('║                     Step 1 of 3: Review Files                         ║');
      console.log('╚═══════════════════════════════════════════════════════════════════════╝');
      console.log('');

      const sensitiveFiles = file ? [file] : [
        path.join(CLAWD_WORKSPACE, 'MEMORY.md'),
        path.join(CLAWD_WORKSPACE, 'SOUL.md'),
      ];

      // Find files that actually exist
      const existingFiles = sensitiveFiles.filter(f => fs.existsSync(f));

      if (existingFiles.length === 0) {
        console.log('❌ No files found to protect.');
        if (!file) {
          console.log(`   Looked in: ${CLAWD_WORKSPACE}`);
        }
        return;
      }

      console.log('📁 Files to protect:');
      existingFiles.forEach(f => {
        const size = fs.statSync(f).size;
        console.log(`   • ${path.basename(f)} (${(size / 1024).toFixed(1)} KB)`);
      });
      console.log('');

      // ═══════════════════════════════════════════════════════════════════════
      // STEP 2: CONFIRM - Choose mode and confirm
      // ═══════════════════════════════════════════════════════════════════════
      console.log('═══════════════════════════════════════════════════════════════════════');
      console.log('                     Step 2 of 3: Choose Protection                     ');
      console.log('═══════════════════════════════════════════════════════════════════════');

      let selectedMode: ProtectionMode = mode || 'obfuscate';
      let passphrase = secret;

      if (!skipPrompts && !mode) {
        selectedMode = await wizard.selectMode();
      }

      // Mode-specific handling
      if (selectedMode === 'obfuscate') {
        console.log('');
        console.log('┌─────────────────────────────────────────────────────────────────────┐');
        console.log('│  ⚠️  OBFUSCATE ≠ ENCRYPTION                                          │');
        console.log('│  This only stops casual viewing. Anyone with this tool can reverse. │');
        console.log('└─────────────────────────────────────────────────────────────────────┘');
        console.log('');
      } else if (selectedMode === 'keychain') {
        console.log('');
        console.log('┌─────────────────────────────────────────────────────────────────────┐');
        console.log('│  📍 MACHINE-BOUND ENCRYPTION                                         │');
        console.log('│  Files can ONLY be decrypted on THIS computer with YOUR account.    │');
        console.log('│  Moving .enc files to another machine = data loss.                  │');
        console.log('└─────────────────────────────────────────────────────────────────────┘');
        console.log('');
      } else if (selectedMode === 'passphrase') {
        console.log('');
        console.log('┌─────────────────────────────────────────────────────────────────────┐');
        console.log('│  🔐 MAXIMUM SECURITY - NO RECOVERY POSSIBLE                          │');
        console.log('├─────────────────────────────────────────────────────────────────────┤');
        console.log('│  • YOU are 100% responsible for this passphrase                     │');
        console.log('│  • If you lose it, your data is GONE FOREVER                        │');
        console.log('│  • There is NO backdoor, NO support, NO recovery                    │');
        console.log('│  • Not even the developer can help you                              │');
        console.log('└─────────────────────────────────────────────────────────────────────┘');
        console.log('');

        if (!skipPrompts) {
          if (!passphrase) {
            passphrase = await wizard.askSecret('Enter passphrase');
            const confirm = await wizard.askSecret('Confirm passphrase');

            if (passphrase !== confirm) {
              console.log('\n❌ Passphrases do not match. Aborting.');
              return;
            }
          }

          const understood = await wizard.requireConfirmation('I UNDERSTAND');
          if (!understood) {
            console.log('\n❌ Cancelled. You must type "I UNDERSTAND" to proceed.');
            return;
          }
        } else if (!passphrase) {
          console.error('Error: --secret <passphrase> required for passphrase mode');
          process.exit(1);
        }
      }

      if (!skipPrompts) {
        const proceed = await wizard.confirm(`Protect ${existingFiles.length} file(s) with ${selectedMode.toUpperCase()} mode?`);
        if (!proceed) {
          console.log('\n❌ Cancelled. No files were modified.');
          return;
        }
      }

      // ═══════════════════════════════════════════════════════════════════════
      // STEP 3: EXECUTE - Protect files and confirm
      // ═══════════════════════════════════════════════════════════════════════
      console.log('');
      console.log('═══════════════════════════════════════════════════════════════════════');
      console.log('                     Step 3 of 3: Protecting Files                      ');
      console.log('═══════════════════════════════════════════════════════════════════════');
      console.log('');

      const protectedFiles: string[] = [];

      for (const filePath of existingFiles) {
        const ext = MODE_EXTENSIONS[selectedMode];
        const outputPath = filePath + ext;

        // Overwrite protection
        if (fs.existsSync(outputPath) && !force) {
          console.log(`⚠️  Skipped: ${path.basename(outputPath)} already exists (use --force)`);
          continue;
        }

        try {
          const content = fs.readFileSync(filePath, 'utf8');
          let protected_: string;

          switch (selectedMode) {
            case 'obfuscate':
              protected_ = FileProtection.obfuscate(content);
              break;
            case 'keychain':
              protected_ = await FileProtection.encryptKeychain(content);
              break;
            case 'passphrase':
              protected_ = FileProtection.encryptPassphrase(content, passphrase!);
              break;
          }

          fs.writeFileSync(outputPath, protected_);
          protectedFiles.push(outputPath);

          const verb = selectedMode === 'obfuscate' ? 'Obfuscated' : 'Encrypted';
          console.log(`✅ ${verb}: ${path.basename(filePath)} → ${path.basename(outputPath)}`);
        } catch (e: any) {
          console.error(`❌ Failed: ${filePath} - ${e.message}`);
        }
      }

      if (protectedFiles.length > 0) {
        console.log('');
        console.log('┌─────────────────────────────────────────────────────────────────────┐');
        console.log('│  ⚠️  IMPORTANT: Test decryption before deleting originals!           │');
        console.log('├─────────────────────────────────────────────────────────────────────┤');
        console.log('│  Run: npx kokeshi-beanstalk unprotect --file <protected-file>       │');
        console.log('│  Verify the content, THEN delete the original plaintext files.     │');
        console.log('└─────────────────────────────────────────────────────────────────────┘');
        console.log('');
        console.log(`✅ Protected ${protectedFiles.length} file(s) successfully.`);
      }
    } finally {
      wizard.close();
    }
  }

  async unprotectFile(filePath: string, secret?: string, skipPrompts?: boolean): Promise<void> {
    const wizard = new Wizard();

    try {
      // ═══════════════════════════════════════════════════════════════════════
      // STEP 1: EXPLAIN - Show what will be decrypted
      // ═══════════════════════════════════════════════════════════════════════
      console.log('');
      console.log('╔═══════════════════════════════════════════════════════════════════════╗');
      console.log('║              KOKESHI BEANSTALK - UNPROTECT FILE                       ║');
      console.log('║                     Step 1 of 3: Review File                          ║');
      console.log('╚═══════════════════════════════════════════════════════════════════════╝');
      console.log('');

      if (!fs.existsSync(filePath)) {
        console.error(`❌ File not found: ${filePath}`);
        process.exit(1);
      }

      // Read and parse header
      const content = fs.readFileSync(filePath, 'utf8');
      const parsed = FileProtection.parseHeader(content);

      if (!parsed) {
        console.error('❌ Cannot determine protection mode.');
        console.error('   File may not be protected or uses an old format.');
        process.exit(1);
      }

      const mode = parsed.header.mode;
      const outputPath = filePath.replace(/\.(obf|enc|aes)$/, '');
      const fileSize = (fs.statSync(filePath).size / 1024).toFixed(1);

      console.log('📁 File details:');
      console.log(`   • File: ${path.basename(filePath)}`);
      console.log(`   • Size: ${fileSize} KB`);
      console.log(`   • Mode: ${mode.toUpperCase()}`);
      console.log(`   • Protected: ${new Date(parsed.header.createdAt).toLocaleString()}`);
      console.log('');
      console.log(`📤 Output: ${path.basename(outputPath)}`);
      console.log('');

      // ═══════════════════════════════════════════════════════════════════════
      // STEP 2: CONFIRM - Get passphrase if needed, confirm action
      // ═══════════════════════════════════════════════════════════════════════
      console.log('═══════════════════════════════════════════════════════════════════════');
      console.log('                     Step 2 of 3: Confirm Decryption                    ');
      console.log('═══════════════════════════════════════════════════════════════════════');
      console.log('');

      let passphrase = secret;

      if (mode === 'passphrase') {
        if (!passphrase && !skipPrompts) {
          passphrase = await wizard.askSecret('Enter passphrase');
        } else if (!passphrase) {
          console.error('Error: --secret <passphrase> required for passphrase-protected files');
          process.exit(1);
        }
      }

      if (!skipPrompts) {
        const proceed = await wizard.confirm('Proceed with decryption?');
        if (!proceed) {
          console.log('\n❌ Cancelled. No changes were made.');
          return;
        }
      }

      // ═══════════════════════════════════════════════════════════════════════
      // STEP 3: EXECUTE - Decrypt and confirm
      // ═══════════════════════════════════════════════════════════════════════
      console.log('');
      console.log('═══════════════════════════════════════════════════════════════════════');
      console.log('                     Step 3 of 3: Decrypting File                       ');
      console.log('═══════════════════════════════════════════════════════════════════════');
      console.log('');

      try {
        let decrypted: string;

        switch (mode) {
          case 'obfuscate':
            decrypted = FileProtection.deobfuscate(content);
            break;
          case 'keychain':
            decrypted = await FileProtection.decryptKeychain(content);
            break;
          case 'passphrase':
            decrypted = FileProtection.decryptPassphrase(content, passphrase!);
            break;
          default:
            throw new Error('Unknown protection mode');
        }

        fs.writeFileSync(outputPath, decrypted);

        const verb = mode === 'obfuscate' ? 'Deobfuscated' : 'Decrypted';
        console.log(`✅ ${verb}: ${path.basename(filePath)} → ${path.basename(outputPath)}`);
        console.log('');
        console.log('┌─────────────────────────────────────────────────────────────────────┐');
        console.log('│  ✅ SUCCESS! File has been restored.                                │');
        console.log('│  You can now safely delete the protected file if desired.          │');
        console.log('└─────────────────────────────────────────────────────────────────────┘');
      } catch (e: any) {
        console.log('');
        if (e.message.includes('auth') || e.message.includes('Unsupported state')) {
          console.error('❌ DECRYPTION FAILED: Authentication error');
          console.error('');
          console.error('   Possible causes:');
          console.error('   • Wrong passphrase');
          console.error('   • File has been tampered with');
          console.error('   • File is corrupted');
        } else {
          console.error(`❌ DECRYPTION FAILED: ${e.message}`);
        }
        process.exit(1);
      }
    } finally {
      wizard.close();
    }
  }
}

// ---------- CLI ----------
interface ParsedArgs {
  command: string;
  jitter: Partial<JitterConfig>;
  secret?: string;
  file?: string;
  mode?: ProtectionMode;
  force?: boolean;
  yes?: boolean;  // Skip all prompts (for automation)
}

function parseFlags(args: string[]): ParsedArgs {
  let command = 'help';
  const jitter: Partial<JitterConfig> = {};
  let secret: string | undefined;
  let file: string | undefined;
  let mode: ProtectionMode | undefined;
  let force = false;
  let yes = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      if (arg === '--jitter-min' && args[i + 1]) jitter.minMs = parseInt(args[++i]);
      if (arg === '--jitter-max' && args[i + 1]) jitter.maxMs = parseInt(args[++i]);
      if (arg === '--prime-multiplier' && args[i + 1]) jitter.primeMultiplier = parseInt(args[++i]);
      if (arg === '--fib-multiplier' && args[i + 1]) jitter.fibMultiplier = parseInt(args[++i]);
      if (arg === '--secret' && args[i + 1]) secret = args[++i];
      if (arg === '--file' && args[i + 1]) file = args[++i];
      if (arg === '--mode' && args[i + 1]) mode = args[++i] as ProtectionMode;
      if (arg === '--secure') mode = 'keychain';
      if (arg === '--max') mode = 'passphrase';
      if (arg === '--force') force = true;
      if (arg === '--yes' || arg === '-y') yes = true;
    } else if (!command || command === 'help') {
      command = arg;
    }
  }
  return { command, jitter, secret, file, mode, force, yes };
}

const args = process.argv.slice(2);
const { command, jitter, secret, file, mode, force, yes } = parseFlags(args);
const beanstalk = new KokeshiBeanstalk(jitter);

(async () => {
  switch (command) {
    case 'scan':
      await beanstalk.scan();
      break;
    case 'harden':
      await beanstalk.hardenConfig(yes);
      break;
    case 'audit':
      await beanstalk.audit();
      break;
    case 'monitor':
      beanstalk.monitor();
      break;

    // Protection commands
    case 'protect':
      await beanstalk.protectFiles(mode, secret, file, force, yes);
      break;
    case 'unprotect':
      if (!file) {
        console.error('Usage: kokeshi-beanstalk unprotect --file <path>');
        process.exit(1);
      }
      await beanstalk.unprotectFile(file, secret, yes);
      break;

    // Legacy commands (deprecated)
    case 'encrypt':
      if (!secret) {
        console.error('Usage: kokeshi-beanstalk encrypt --secret <passphrase>');
        process.exit(1);
      }
      if (file) {
        SoulEncryption.encryptFile(file, secret);
      } else {
        console.warn('⚠️  DEPRECATION WARNING: "encrypt" is deprecated.');
        console.warn('   Use "protect --mode passphrase --secret <pass>" instead.\n');
        await beanstalk.protectFiles('passphrase', secret, undefined, force, yes);
      }
      break;
    case 'decrypt':
      if (!secret || !file) {
        console.error('Usage: kokeshi-beanstalk decrypt --secret <passphrase> --file <path>');
        process.exit(1);
      }
      SoulEncryption.decryptFile(file, secret);
      break;

    default:
      console.log(`
Kokeshi Beanstalk - Runtime Guardian for Clawdbot
A Darby Tool from PIP Projects Inc.

"Kokeshi Beanstalk never changes system state without explaining
what will happen, asking permission, and confirming success."

Commands:
  scan                                Security scan (read-only, shows how to fix)
  harden                              Guided security hardening (3-step wizard)
  audit                               One-shot audit (with tamper detection)
  monitor [options]                   Continuous monitoring

File Protection (AES-256-GCM AEAD):
  protect [options]                   Guided file protection (3-step wizard)
    --mode obfuscate                  Light scramble (NOT encryption, always reversible)
    --mode keychain                   AES-256-GCM, key in system keychain (machine-bound)
    --mode passphrase --secret <p>    AES-256-GCM, user manages key (no recovery)
    --secure                          Alias for --mode keychain
    --max                             Alias for --mode passphrase
    --file <path>                     Protect specific file
    --force                           Overwrite existing protected files

  unprotect --file <path>             Guided file decryption (3-step wizard)
    --secret <passphrase>             Required for passphrase-protected files

Automation:
  --yes, -y                           Skip all prompts (for scripts)
                                      Example: npx kokeshi-beanstalk harden --yes

Protection Levels:
  ┌─────────────┬──────────┬────────────────────────────────────┐
  │ Mode        │ Security │ Recovery                           │
  ├─────────────┼──────────┼────────────────────────────────────┤
  │ obfuscate   │ Low      │ Always (no key needed)             │
  │ keychain    │ High     │ Via system login (machine-bound)   │
  │ passphrase  │ Maximum  │ User responsible (NO recovery)     │
  └─────────────┴──────────┴────────────────────────────────────┘

Examples:
  npx kokeshi-beanstalk scan                         # check for issues (no changes)
  npx kokeshi-beanstalk harden                       # guided security setup
  npx kokeshi-beanstalk harden --yes                 # auto-fix (no prompts)
  npx kokeshi-beanstalk protect                      # guided file protection
  npx kokeshi-beanstalk protect --secure --yes       # keychain mode (no prompts)
  npx kokeshi-beanstalk unprotect --file MEMORY.md.enc

MIT License - PIP Projects Inc.
github.com/darbybailey/kokeshi-beanstalk
      `);
  }
})();
