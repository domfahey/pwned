# Security Policy

## Supported Versions

Security fixes are applied to the latest release on `main`.

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Instead, report them privately using [GitHub Security Advisories](https://github.com/domfahey/pwned/security/advisories/new). Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof of concept
- Any suggested remediation, if known

You can expect an acknowledgment within 72 hours and updates as the issue is investigated and resolved.

## Security Design Notes

- **API keys:** Pass `HIBP_API_KEY` via environment variable or `.env` rather than `--api-key` to avoid exposure in process listings. API keys are wrapped in `pydantic.SecretStr` and are never sent to unauthenticated endpoints.
- **Passwords:** `pwned password` hashes passwords locally (SHA-1 or NTLM) and sends only the first 5 hex characters to the Pwned Passwords range API (*k*-anonymity). Prefer the interactive prompt or `--stdin` over passing passwords as CLI arguments.
