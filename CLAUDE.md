# Vellum — Envelope Encryption Library for .NET

> **Vellum** _(n.)_ — fine parchment historically used for important documents, charters, and sealed letters. Evokes preservation, authenticity, and secrecy — the core values of envelope encryption.

A provider-agnostic, production-grade envelope encryption library for .NET with DEK lifecycle management, key rotation, and multi-tenant support.

Public library under **Apache 2.0** — patent grant, enterprise-friendly. Published to NuGet.

**Reference plan**: `/home/jadei/Projects/Jacqcouille/jacquouille-orchestrator/docs/vellum-library-plan.md`

---

## Design principles

Non-derivable from the code — these are the decisions the code is meant to obey.

1. **Provider-agnostic** — Vault, AWS KMS, Azure Key Vault, GCP KMS, static (dev) are first-class
2. **Storage-agnostic** — EF Core by default, but any storage can implement `IEncryptionKeyStore`
3. **No custom crypto** — exclusively AES-GCM via `System.Security.Cryptography`. Never invent.
4. **Multi-tenant by construction** — keys scoped via an opaque `Scope` string (`"bus:123"`, `"tenant:456"`). Vellum must never know about buses, messages or any Jacquouille domain type.
5. **Fail closed** — any error in key resolution, wrap or unwrap must throw. Never silently degrade.
6. **Zero allocation where possible** — `Span<byte>` / `Memory<byte>` on the hot path
7. **Testable** — every interface mockable; in-memory provider + storage for unit tests
8. **No background services in Core** — rotation is opt-in via `Vellum.Rotation`

---

## Not built yet

Everything under `src/` exists and is published. These are the packages the structure anticipates and that do **not** exist:

- `Vellum.AzureKeyVault`, `Vellum.AwsKms`, `Vellum.GcpKms` — the remaining KEK providers
- `Vellum.AspNetCore` — DI extensions + health checks
- `Vellum` — the meta-package

A new KEK provider implements `IKeyEncryptionProvider`; a new store implements `IEncryptionKeyStore`. Both live in `Vellum.Abstractions` — read them there rather than trusting a description here.

---

## Before 1.0

Hardening not yet done, and worth knowing before designing anything that would make it harder:
`pg_advisory_xact_lock` on rotation, property-based tests (FsCheck), fuzzing, a written threat model,
an external audit, benchmarks, and migration guides.

---

## C# Requirements

Conventions non négociables (types explicites, primary constructors, LoggerMessage, un type par
fichier, etc.) : voir l'agent `csharp-developer` (`~/.claude/agents/csharp-developer.md`) —
appliquées automatiquement, pas répétées ici.
