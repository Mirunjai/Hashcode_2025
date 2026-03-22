# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.5.x | ✅ Yes |
| < 1.5 | ❌ No |

## Reporting a vulnerability

LinkLens is a security tool — responsible disclosure matters.

If you find a bypass technique, false negative pattern, or vulnerability:

1. **Do not** open a public GitHub issue
2. Open a GitHub issue titled `[SECURITY] Brief description`
   and mark it as confidential, or contact the maintainers directly
3. Include: the bypass method, a reproducible example URL or technique,
   and the expected vs actual verdict

We will respond within 7 days and credit you in the fix.

## Scope

In scope:
- URL model bypass techniques (URLs that should score MALICIOUS but score SAFE)
- OCR evasion techniques that could fool the content scanner
- DOM checker bypasses
- Any technique that allows a phishing page to pass as SAFE

Out of scope:
- The backend running on localhost (by design, not a network service)
- Browser fingerprinting or tracking concerns
- Performance issues