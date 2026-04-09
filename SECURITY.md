# Security Policy

## Supported Versions

Vellum is currently in `0.1.x-preview`. **Preview versions are not supported for production use** and receive security fixes on a best-effort basis.

A formal support policy will be published with the `1.0.0` release.

| Version | Supported |
|---------|-----------|
| `0.1.x-preview` | Best-effort only |
| `< 0.1.0` | No |

## Reporting a Vulnerability

**Do not file public GitHub issues for security vulnerabilities.**

Instead, please report vulnerabilities privately via:

- **GitHub Security Advisories**: https://github.com/vellum-dotnet/vellum/security/advisories/new
- **Email**: security@vellum.dev _(placeholder — to be finalized before `0.1.0-preview`)_

Please include:

1. A description of the vulnerability and its impact.
2. Steps to reproduce (proof of concept if possible).
3. Affected versions or commit hashes.
4. Suggested mitigations, if any.

We will acknowledge receipt within **72 hours** and provide a target timeline for a fix within **7 days**.

## Disclosure Policy

- We follow **coordinated disclosure**.
- We will work with you to validate the report, develop a fix, and coordinate a public announcement.
- Security advisories will be published via GitHub Security Advisories and the `CHANGELOG.md`.

## Security Principles

Vellum is a cryptography library. We take the following principles seriously:

1. **No custom crypto.** Vellum uses exclusively `System.Security.Cryptography.AesGcm`. We never invent primitives.
2. **Fail closed.** Any error in key resolution, wrap, or unwrap throws. Vellum never silently degrades to plaintext.
3. **Memory hygiene.** Sensitive byte arrays are cloned before leaving caches and are expected to be zeroed by callers after use.
4. **No secrets in logs.** Vellum never logs DEKs, KEKs, nonces, or ciphertexts. Structured logging uses identifiers only.
5. **`Vellum.Static` is for development only** and logs a loud warning when instantiated. It must never be used in production.

## Known Limitations (pre-`1.0.0`)

- No external cryptographic audit has been performed yet.
- No fuzzing harness is in place yet.
- `pg_advisory_xact_lock` for DEK creation is planned for `1.0`; until then, DEK creation relies on a defense-in-depth pattern (double-check, unique index, catch 23505, re-read winner, detach failed entity).

These will be addressed in Phase 5 (Hardening for 1.0).
