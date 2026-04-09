# Vellum — Envelope Encryption Library for .NET

> **Vellum** _(n.)_ — fine parchment historically used for important documents, charters, and sealed letters. Evokes preservation, authenticity, and secrecy — the core values of envelope encryption.

A provider-agnostic, production-grade envelope encryption library for .NET with DEK lifecycle management, key rotation, and multi-tenant support.

---

## Mission

Extract the DEK/KEK envelope encryption code from `jacqcloud-buses` into a standalone, public .NET library that fills a real gap in the ecosystem.

**Reference plan**: `/home/jadei/Projects/Jacqcouille/jacquouille-orchestrator/docs/vellum-library-plan.md`

---

## Source of origin

The production code being extracted lives in:
`/home/jadei/Projects/Jacqcouille/jacqcloud-buses/`

Key files to port (Domain interfaces + Infrastructure implementations):

### Domain
- `src/JacqCloud.Buses.Domain/Interfaces/IEncryptionService.cs`
- `src/JacqCloud.Buses.Domain/Interfaces/IDekManager.cs`
- `src/JacqCloud.Buses.Domain/Interfaces/IPayloadEncryptor.cs`
- `src/JacqCloud.Buses.Domain/Interfaces/IBusEncryptionKeyRepository.cs`
- `src/JacqCloud.Buses.Domain/ValueObjects/ActiveDek.cs`
- `src/JacqCloud.Buses.Domain/ValueObjects/EncryptedPayload.cs`
- `src/JacqCloud.Buses.Domain/ValueObjects/PayloadEncryptionResult.cs`
- `src/JacqCloud.Buses.Domain/Entities/BusEncryptionKey.cs`

### Infrastructure
- `src/JacqCloud.Buses.Infrastructure/Encryption/VaultEncryptionService.cs`
- `src/JacqCloud.Buses.Infrastructure/Encryption/DekManager.cs`
- `src/JacqCloud.Buses.Infrastructure/Encryption/PayloadEncryptor.cs`
- `src/JacqCloud.Buses.Infrastructure/Encryption/DekRotationBackgroundService.cs`
- `src/JacqCloud.Buses.Infrastructure/Encryption/EncryptionOptions.cs`
- `src/JacqCloud.Buses.Infrastructure/Persistence/Runtime/Repositories/BusEncryptionKeyRepository.cs`
- `src/JacqCloud.Buses.Infrastructure/Extensions/EncryptionServiceCollectionExtensions.cs`

### Tests
- `tests/JacqCloud.Buses.Api.Tests/Encryption/VaultEncryptionServiceTests.cs`
- `tests/JacqCloud.Buses.Api.Tests/Encryption/DekManagerTests.cs`
- `tests/JacqCloud.Buses.Api.Tests/Encryption/PayloadEncryptorTests.cs`
- `tests/JacqCloud.Buses.Api.Tests/Encryption/DekRotationBackgroundServiceTests.cs`

---

## Target package structure

```
Vellum (meta-package)
├── Vellum.Abstractions              # Interfaces + value objects (zero deps)
├── Vellum.Core                      # DekManager + PayloadEncryptor
├── KEK Providers
│   ├── Vellum.Vault                 # HashiCorp Vault Transit
│   ├── Vellum.AzureKeyVault         # Azure Key Vault
│   ├── Vellum.AwsKms                # AWS KMS
│   ├── Vellum.GcpKms                # Google Cloud KMS
│   └── Vellum.Static                # Dev/test only (INSECURE)
├── Storage
│   ├── Vellum.EntityFrameworkCore   # EF Core + migrations
│   └── Vellum.InMemory              # Tests/dev
├── Vellum.Rotation                  # Optional background rotation
└── Vellum.AspNetCore                # DI extensions + health checks
```

---

## Design principles

1. **Provider-agnostic** — Vault, AWS KMS, Azure Key Vault, GCP KMS, static (dev) are first-class
2. **Storage-agnostic** — EF Core by default, but any storage can implement `IEncryptionKeyStore`
3. **No custom crypto** — exclusively AES-GCM via `System.Security.Cryptography`. Never invent.
4. **Multi-tenant by construction** — keys scoped via an opaque `Scope` string
5. **Fail closed** — any error in key resolution, wrap, unwrap must throw. Never silently degrade.
6. **Zero allocation where possible** — use `Span<byte>` / `Memory<byte>` on the hot path
7. **Testable** — every interface mockable; in-memory provider + storage for unit tests
8. **No background services in Core** — rotation is opt-in via `Vellum.Rotation`

---

## Key refactoring from source code

### 1. Decouple from "Bus"

Current code uses `BusInstanceId` and `OrganizationId` everywhere. Vellum must not know about buses.

Replace with an opaque `Scope` string:
```csharp
public sealed record EncryptionKey(
    Guid KeyId,
    string Scope,              // "bus:123", "tenant:456", "user:789"
    string WrappedDek,
    int ProviderVersion,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    bool IsActive
);
```

### 2. Abstract the KEK provider

```csharp
public interface IKeyEncryptionProvider
{
    string ProviderName { get; }
    Task<WrappedKey> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken ct);
    Task<byte[]> UnwrapAsync(WrappedKey wrapped, CancellationToken ct);
}
```

### 3. Abstract the DEK storage

```csharp
public interface IEncryptionKeyStore
{
    Task<EncryptionKey?> GetActiveAsync(string scope, CancellationToken ct);
    Task<EncryptionKey?> GetByIdAsync(Guid keyId, CancellationToken ct);
    Task<EncryptionKey> CreateAsync(EncryptionKey key, CancellationToken ct);
    Task DeactivateAllAsync(string scope, CancellationToken ct);
    Task<IReadOnlyList<EncryptionKey>> GetHistoricalAsync(string scope, CancellationToken ct);
}
```

### 4. Remove Jacquouille domain references

`Message`, `ContextEntry`, `Bus` must not appear anywhere in Vellum.

### 5. Rotation becomes opt-in

Move `DekRotationBackgroundService` into a dedicated `Vellum.Rotation` package.

---

## C# Requirements (non-negotiable)

- **NEVER use `var`** — always explicit types (`string`, `List<T>`, `ITokenBlacklistService`, etc.)
- **Primary constructors** (C# 12+) for classes with DI dependencies
- **LoggerMessage source generators** ([LoggerMessage] + partial class) — never direct `_logger.LogInformation(...)`
- **Naming**: `_camelCase` for private fields, follow `.editorconfig`
- **Options pattern**: use `Action<TOptions>` not `IConfiguration`
- **One type per file**: file name matches the type name exactly
- **Sealed by default** — every class `sealed` unless explicitly designed for inheritance
- **Nullable reference types enabled** project-wide
- **No exception swallowing** — rethrow or log and rethrow; never silently continue
- **`ConfigureAwait(false)` in library code** (Vellum is a library, not an application)

---

## Jacquouille bus workflow

### Au demarrage (obligatoire)
```
1. get_context()
2. Lire tasks/lessons.md si le fichier existe → appliquer les lecons apprises
3. Commencer le travail
```

### Quand tu produis quelque chose que les autres doivent connaitre
```
1. set_context(key="vellum.exports", value={...}, set_by="vellum")
2. Si breaking change → broadcast(from="vellum", type="breaking_change", payload={...})
```

### Types de messages

| Type | Usage |
|------|-------|
| `query` | Poser une question a un autre agent |
| `response` | Repondre a une query |
| `api_contract` | Partager une interface (endpoints, types, schemas) |
| `code_result` | Un module/composant est pret ou modifie |
| `domain_event` | Un evenement metier s'est produit |
| `breaking_change` | Changement incompatible qui impacte les autres |
| `context_update` | Mise a jour du contexte partage |

### Gestion des taches

| Fichier | Usage |
|---------|-------|
| `tasks/todo.md` | Plan et suivi du travail en cours (items cochables) |
| `tasks/lessons.md` | Lecons apprises — patterns a suivre et erreurs a eviter |
| `set_context` | Progress partage visible par tous les agents |

### Workflow principes

- **Planifier avant de coder** — toute tache non-triviale (3+ etapes) → plan dans `tasks/todo.md`
- **Verifier avant de reporter** — jamais marquer une tache finie sans tests verts
- **Exiger l'elegance** — challenger son travail, prendre du recul si fix hacky
- **Boucle d'amelioration** — apres TOUTE correction → mettre a jour `tasks/lessons.md`
- **Resolution autonome des bugs** — fixer les erreurs recues via `query`/`code_result` directement
- **Simplicite** — chaque changement aussi simple que possible, impact minimal

---

## Phases

### Phase 1 — Core MVP (~10-12 jours)
Solution scaffold, extract Abstractions + Core + Vault + Static + EF + InMemory, port tests, CI, docs.
**Deliverable**: `0.1.0-preview` on NuGet (not for production).

### Phase 2 — Dogfood in Jacquouille (~5 jours)
Replace `jacqcloud-buses` encryption code with Vellum packages, validate production.

### Phase 3 — Cloud providers
Vellum.AzureKeyVault, Vellum.AwsKms, Vellum.GcpKms.

### Phase 4 — Rotation and hosting
Vellum.Rotation, Vellum.AspNetCore, observability (ActivitySource, Meter).

### Phase 5 — Hardening for 1.0
pg_advisory_xact_lock, property-based tests (FsCheck), fuzzing, threat model, external audit, benchmarks, migration guides.

---

## Licensing

Apache 2.0. Patent grant, enterprise-friendly, permissive.
