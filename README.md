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

## Usage

### Harden Configuration

Scans your `~/.clawdbot/clawdbot.json` and fixes insecure defaults.

```bash
npx kokeshi-beanstalk harden
```

### Encrypt Data

Encrypts your `MEMORY.md` and `SOUL.md` so they aren't readable if your machine is stolen.

```bash
npx kokeshi-beanstalk encrypt --secret "my-super-secret-password"
```

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
