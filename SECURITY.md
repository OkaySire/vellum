# Security Policy

## Supported Versions

The current release line is `0.2.x`. Vellum is pre-`1.0`: security fixes land on the current minor release line, and the previous line receives critical security fixes on a best-effort basis until the next minor ships.

A formal support policy will be published with the `1.0.0` release.

| Version | Supported |
|---------|-----------|
| `0.2.x` | Yes — current release line |
| `0.1.x` | Critical security fixes only (best-effort) |
| `0.1.x-preview` | No — upgrade to `0.2.x` |
| `< 0.1.0` | No |

## Reporting a vulnerability

Please report security vulnerabilities via **[GitHub Security Advisories](https://github.com/OkaySire/vellum/security/advisories/new)**.

This creates a private channel between you and the maintainers. We will:
- Acknowledge receipt within 72 hours
- Validate the report and develop a fix
- Coordinate a public disclosure with you (typically 90 days max)
- Credit you in the release notes if you wish

Please do NOT report vulnerabilities via public GitHub issues or discussions.

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
