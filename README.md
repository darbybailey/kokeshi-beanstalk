# Kokeshi Beanstalk 🌱

**Runtime security guardian for Clawdbot installations.**

A Darby Tool from [PIP Projects Inc.](https://pipprojects.com)

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-win%20%7C%20mac%20%7C%20linux-lightgrey)

## The Problem

Clawdbot is amazing, but the default configuration often exposes your API keys and chat history to the public internet.

**Kokeshi Beanstalk** is a runtime sentinel that runs alongside your bot to:
1. **Lock the doors** (Enforce localhost binding & auth tokens)
2. **Watch the windows** (Detect exposure & port scans)
3. **Encrypt the secrets** (Protect `MEMORY.md` at rest)

## Quick Start

```bash
# 1. Run the hardening script (One-time setup)
npx kokeshi-beanstalk harden

# 2. Start the monitor
npx kokeshi-beanstalk monitor
```

## Features

### 🛡️ Defense in Depth

- **Network**: Monitors port 18789 for 0.0.0.0 binding
- **Config**: Validates clawdbot.json against security best practices
- **Storage**: AES-256 encryption for sensitive memory files

### 🎲 Prime-Fibonacci Jitter

Most security monitors check at fixed intervals (e.g., every 10s). Attackers can time their probes to slip in between checks.

Kokeshi Beanstalk uses a hybrid timing algorithm:

```
Interval = (Prime × Multiplier) + (Fibonacci × Variation)
```

This creates a non-harmonic, unpredictable monitoring pattern that is mathematically difficult to evade.

### 🌸 Fibonacci Bloom Filter

Tracks suspicious connection attempts using a space-efficient probabilistic data structure. It remembers repeat probes without needing a heavy database.

## 🧠 Security Model: Entropy vs. Pattern

Kokeshi Beanstalk uses a two-layer timing defense based on **Kerckhoffs's Principle**: the algorithm is public, but the entropy is private.

### Layer 1: The Weave (Coverage)
The Prime-Fibonacci slapback algorithm ensures monitoring intervals are distributed non-linearly across the time spectrum. This prevents **harmonic resonance** — the predictable gaps that occur with fixed-interval monitoring (e.g., checking every 10 seconds allows attackers to safely probe at second 11).

* **Prime numbers** provide gap-free coverage.
* **Fibonacci variation** adds amplitude diversity.
* **Figure-8 slapback** prevents linear sequence prediction.
* **φ (phi)** amplitude minimizes harmonic patterns.

### Layer 2: The Noise (Unpredictability)
The actual trigger time is non-deterministic. Even with full knowledge of the source code and current cycle state, an attacker cannot predict the next check due to multiple runtime entropy sources:

| Source | Entropy | Notes |
| :--- | :--- | :--- |
| `crypto.randomBytes(2)` | 0–500ms | CSPRNG-derived true random |
| `process.hrtime()[1]` | 0–100ns | CPU nanosecond jitter |
| **Temporal Drift** | ×17 daily variants | Based on server clock state |

**Combined entropy space:** ~42 million possible intervals per base value.

### What This Means

| With Source Code, Attacker Knows | Attacker Still Cannot Know |
| :--- | :--- |
| The prime weave pattern | Your CSPRNG state |
| The phi-derived amplitude | Your CPU's nanosecond counter |
| The slapback depth (144) | Your exact server clock |
| The formula structure | **The next interval** |

> **Result:** The algorithm determines the *window* of the check. Entropy determines the *exact moment*. This makes timing attacks computationally infeasible — not because the math is secret, but because the randomness is real.

## Usage

### 🔍 Security Scan

Check your installation for security issues without making changes. Shows a security score and tells you exactly how to fix each issue.

```bash
npx kokeshi-beanstalk scan
```

**Example output:**
```
╔═══════════════════════════════════════════════════════════════════════╗
║              KOKESHI BEANSTALK - SECURITY SCAN                        ║
╠═══════════════════════════════════════════════════════════════════════╣
║  ❌ Security Score: 35/100  Grade: F                                  ║
║  [███████░░░░░░░░░░░░░]                                               ║
╚═══════════════════════════════════════════════════════════════════════╝

🔴 [CRITICAL] Your bot is visible to the entire internet
   Technical: Gateway bound to 0.0.0.0 instead of 127.0.0.1
   Fix: Edit ~/.clawdbot/clawdbot.json: set "gateway.bind": "127.0.0.1"

🟠 [HIGH] Your memories are stored in plain text
   Technical: MEMORY.md exists unencrypted
   Fix: npx kokeshi-beanstalk protect --secure --file ~/clawd/MEMORY.md

🟡 [MEDIUM] Your bot accepts messages from anyone
   Technical: DM policy is "open" instead of "pairing"
   Fix: Edit config: set "channels.dmPolicy": "pairing"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 CRITICAL = You could be hacked right now
🟠 HIGH     = Fix this today
🟡 MEDIUM   = Recommended improvement
🔵 LOW      = Nice to have

───────────────────────────────────────────────────────────────────────
Don't want to fix manually? Run: npx kokeshi-beanstalk harden
───────────────────────────────────────────────────────────────────────
```

### Harden Configuration (Auto-Fix)

Don't want to fix issues manually? This command auto-fixes everything.

```bash
npx kokeshi-beanstalk harden
```

### 🔐 File Protection Levels

Kokeshi Beanstalk offers three levels of file protection:

| Mode | Security | Recovery | Best For |
|------|----------|----------|----------|
| `obfuscate` | Low | Always (no key needed) | Casual privacy, stops shoulder surfers |
| `keychain` | High | Via system login | Most users - secure but can't lose key |
| `passphrase` | Maximum | User responsible | High security needs, compliance |

```bash
# Quick protect (obfuscate - always recoverable)
npx kokeshi-beanstalk protect

# Secure protect (keychain - recoverable via system login)
npx kokeshi-beanstalk protect --secure

# Maximum protect (passphrase - YOU manage the key)
npx kokeshi-beanstalk protect --max --secret "your-long-passphrase"

# Unprotect (auto-detects mode)
npx kokeshi-beanstalk unprotect --file MEMORY.md.obf
npx kokeshi-beanstalk unprotect --file MEMORY.md.enc
npx kokeshi-beanstalk unprotect --file MEMORY.md.aes --secret "your-passphrase"
```

**File extensions by mode:**
- `.obf` = obfuscated (reversible, no key)
- `.enc` = keychain encrypted (key in system keychain)
- `.aes` = passphrase encrypted (user manages key)

**Recommendation:** Use `--secure` (keychain) for most cases. Only use `--max` if you have specific compliance requirements and a password manager.

### Monitor

Runs the continuous sentinel process.

```bash
npx kokeshi-beanstalk monitor --jitter-min 1000 --jitter-max 30000
```

### Install Globally (Optional)

```bash
npm install -g kokeshi-beanstalk
```

## Security Coverage

| Vulnerability | Status |
|---------------|--------|
| Unauth Admin UI | ✅ SOLVED |
| Public Exposure | ✅ SOLVED |
| RCE via Skills | ✅ MITIGATED |
| Plaintext Memory | ✅ SOLVED |

## Author

**Darby Bailey McDonough, Ph.D.**
[GitHub: @darbybailey](https://github.com/darbybailey)

## Acknowledgments

Built with assistance from Claude (Anthropic), Gemini (Google), and Grok (xAI).

## License

MIT © PIP Projects Inc.
