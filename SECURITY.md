# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ Active          |

## Reporting a Vulnerability

If you discover a security vulnerability in bola itself (not in a target
application), please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email: **mutasem@bola.dev**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 1 week
- **Fix timeline:** Depends on severity, typically within 2 weeks

## Scope

Security issues in bola's own code are in scope:
- Authentication token leakage in logs or reports
- Proxy certificate handling vulnerabilities
- SQLite injection in internal queries
- Path traversal in HAR import

Out of scope:
- Vulnerabilities in target applications (that's what bola is for!)
- Issues in third-party dependencies (report upstream)

## Responsible Disclosure

We follow responsible disclosure practices. We will:
- Acknowledge your report promptly
- Work with you to understand the issue
- Credit you in the fix (unless you prefer anonymity)
- Not take legal action against good-faith researchers
