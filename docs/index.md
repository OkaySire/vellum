# Vellum

> **Vellum** _(n.)_ — fine parchment historically used for important documents, charters, and
> sealed letters. Evokes preservation, authenticity, and secrecy — the core values of envelope
> encryption.

**Vellum** is a provider-agnostic envelope encryption library for .NET with DEK lifecycle
management, key rotation, and multi-tenant support. It does not implement any cryptographic
primitive of its own — all authenticated encryption goes through
`System.Security.Cryptography.AesGcm`.

> **Status: `0.2.0`.** Pre-1.0: API may evolve, breaking changes allowed per semver — see
> the [CHANGELOG](https://github.com/OkaySire/vellum/blob/main/CHANGELOG.md) for the 0.2.0
> breaking changes. Cloud KMS providers (Azure Key Vault, AWS KMS, GCP KMS) land in `0.3.0`;
> ASP.NET Core health checks (`Vellum.AspNetCore`) are planned. See the
> [roadmap in the top-level README](https://github.com/OkaySire/vellum#packages) for the
> exact package list.

## Where to start

| I want to… | Read |
|---|---|
| Install Vellum and encrypt my first payload | [Getting started](getting-started.md) |
| Understand how the pieces fit together | [Architecture](architecture.md) |
| Get a short answer to a specific question | [FAQ](faq.md) |
| Pick between Vellum and another library | [Comparison](comparison.md) |
| Rotate DEKs and KEKs safely (including `min_decryption_version`) | [Key rotation runbook](kek-rotation.md) |
| Port my existing custom encryption layer to Vellum | [Migrating from a custom implementation](migrations/from-custom.md) |
| Bridge `appsettings.json` values into Vellum's `Action<TOptions>` overloads | [Consumer options bridging](consumer-options-bridging.md) |
| Look up a specific interface / record / method | [API reference](api/) |

## Packages at a glance

| Package | Purpose | Status |
|---|---|---|
| `Vellum.Abstractions` | Interfaces and value objects. Zero runtime dependencies. | Shipped |
| `Vellum.Core` | `DekManager` + `PayloadEncryptor`. AES-GCM via `System.Security.Cryptography`. | Shipped |
| `Vellum.Vault` | HashiCorp Vault Transit KEK provider. | Shipped |
| `Vellum.Static` | Static-key KEK provider for dev and test only. **Never for production.** | Shipped |
| `Vellum.EntityFrameworkCore` | EF Core-backed `IEncryptionKeyStore`. | Shipped |
| `Vellum.InMemory` | In-memory `IEncryptionKeyStore` for tests and samples. | Shipped |
| `Vellum.AzureKeyVault` | Azure Key Vault KEK provider. | Planned (0.3.0) |
| `Vellum.AwsKms` | AWS KMS KEK provider. | Planned (0.3.0) |
| `Vellum.GcpKms` | GCP KMS KEK provider. | Planned (0.3.0) |
| `Vellum.Rotation` | Opt-in background DEK rotation hosted service. | Shipped |
| `Vellum.AspNetCore` | Health checks and DI helpers. | Planned |

## Design principles

1. **Provider-agnostic** — Vault, AWS KMS, Azure Key Vault, GCP KMS, and static (dev) are
   first-class. Your choice of KEK backend is a package reference, not a fork of the library.
2. **Storage-agnostic** — EF Core by default, but any persistence layer can implement
   `IEncryptionKeyStore`.
3. **No custom crypto** — exclusively AES-GCM via `System.Security.Cryptography`.
4. **Multi-tenant by construction** — keys are partitioned by an opaque `Scope` string that
   Vellum never interprets.
5. **Fail closed** — any error in key resolution, wrap, or unwrap throws. Vellum never
   silently returns plaintext.
6. **Zero allocation where possible** — `Span<byte>` / `Memory<byte>` on the hot path,
   `ValueTask` for cache-hit returns from `IDekManager`.
7. **Testable** — every interface is mockable; the in-memory provider and store can drive
   unit tests end-to-end without touching a real KEK backend.
8. **No background services in Core** — rotation is opt-in via `Vellum.Rotation`. A plain
   dependency on `Vellum.Core` never starts a timer or a hosted service.

## Security

Vellum's threat model, vulnerability disclosure process, and security posture live in
[`SECURITY.md`](https://github.com/OkaySire/vellum/blob/main/SECURITY.md) at the top of the
repository.

## License

Apache License 2.0. See
[`LICENSE`](https://github.com/OkaySire/vellum/blob/main/LICENSE).
