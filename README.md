# Vellum

> **Vellum** _(n.)_ — fine parchment historically used for important documents, charters, and sealed letters. Evokes preservation, authenticity, and secrecy — the core values of envelope encryption.

**Vellum** is a provider-agnostic, production-grade **envelope encryption library for .NET** with DEK lifecycle management, key rotation, and multi-tenant support.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4)](https://dotnet.microsoft.com/)

> **Status: `0.1.0-preview` — Not yet ready for production. API may change.**

---

## What is envelope encryption?

Envelope encryption is a pattern where:

1. A **Data Encryption Key (DEK)** encrypts the actual payload (via AES-GCM).
2. A **Key Encryption Key (KEK)**, managed by a secure provider (Vault, KMS, HSM), wraps the DEK.
3. Only the wrapped DEK is stored alongside the ciphertext.
4. Decryption requires access to the KEK provider to unwrap the DEK.

This pattern lets you rotate keys at the KEK level without re-encrypting every payload, and ensures that a database dump alone is not sufficient to decrypt data.

## Packages

| Package | Purpose |
|---|---|
| `Vellum.Abstractions` | Interfaces + value objects. Zero dependencies. |
| `Vellum.Core` | `DekManager` + `PayloadEncryptor`. AES-GCM via `System.Security.Cryptography`. |
| `Vellum.Vault` | HashiCorp Vault Transit KEK provider. |
| `Vellum.AzureKeyVault` | Azure Key Vault KEK provider _(Phase 3)_. |
| `Vellum.AwsKms` | AWS KMS KEK provider _(Phase 3)_. |
| `Vellum.GcpKms` | Google Cloud KMS KEK provider _(Phase 3)_. |
| `Vellum.Static` | Static key provider **for dev/test only — INSECURE**. |
| `Vellum.EntityFrameworkCore` | EF Core-backed key store. |
| `Vellum.InMemory` | In-memory key store for tests. |
| `Vellum.Rotation` | Opt-in background DEK rotation _(Phase 4)_. |
| `Vellum.AspNetCore` | DI extensions + health checks _(Phase 4)_. |

## Quickstart

_(coming soon — Phase 1 in progress)_

## Design principles

1. **Provider-agnostic** — Vault, AWS KMS, Azure Key Vault, GCP KMS, static (dev) are first-class.
2. **Storage-agnostic** — EF Core by default, but any storage can implement `IEncryptionKeyStore`.
3. **No custom crypto** — exclusively AES-GCM via `System.Security.Cryptography`.
4. **Multi-tenant by construction** — keys scoped via an opaque `Scope` string.
5. **Fail closed** — any error in key resolution, wrap, or unwrap throws. Never silently degrades.
6. **Zero allocation where possible** — `Span<byte>` / `Memory<byte>` on the hot path.
7. **Testable** — every interface mockable; in-memory provider + store for unit tests.
8. **No background services in Core** — rotation is opt-in via `Vellum.Rotation`.

## Security

Please see [SECURITY.md](SECURITY.md) for responsible disclosure and threat model.

## License

Apache License 2.0. See [LICENSE](LICENSE).
