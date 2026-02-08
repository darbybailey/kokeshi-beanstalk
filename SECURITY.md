# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Kokeshi Beanstalk, please report it responsibly.

**Email:** darby@pipprojects.com
**Subject line:** `[SECURITY] kokeshi-beanstalk: <brief description>`

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Impact assessment (what an attacker could do)

We aim to acknowledge reports within 48 hours and provide a fix timeline within 7 days.

## Scope

**In scope:**
- Symlink/hardlink/path traversal bypasses on file write paths
- Encryption key leakage (secrets appearing in logs, process lists, or error messages)
- Authentication bypass in config hardening (e.g., token not enforced)
- AES-256-GCM implementation flaws (IV reuse, auth tag bypass, key derivation weakness)
- Prototype pollution or injection via parsed config/JSON
- Command injection via keychain or system commands
- TOCTOU race conditions on file operations

**Out of scope:**
- Obfuscate mode reversibility (this is by design and clearly labeled)
- Jitter timing predictability (jitter is scheduling noise, not a security boundary)
- Vulnerabilities in Clawdbot itself (report to the Clawdbot project)
- npm/npx supply chain attacks (report to npm)
- OS keychain vulnerabilities (report to your OS vendor)
- Denial of service via resource exhaustion (this is a local CLI tool)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.3.x   | Yes       |
| < 1.3   | No        |

## Disclosure Policy

We follow coordinated disclosure. Please allow 90 days for a fix before public disclosure. We will credit reporters in the changelog unless anonymity is requested.
