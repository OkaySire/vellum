# Vellum — TODO

Plan d'implementation base sur `jacquouille-orchestrator/docs/vellum-library-plan.md`.

## Phase 1 — Core MVP

### 1.1 Solution scaffold
- [x] Creer `Vellum.slnx` (format .NET 10 par defaut)
- [x] Structure `src/` avec sous-dossiers par package
- [x] Structure `tests/` (vide, projets a ajouter par package)
- [x] Structure `samples/` (vide, sample a ajouter)
- [x] `Directory.Build.props` commun (nullable, langversion, TWarnings=error, analyzers AllEnabled)
- [x] `Directory.Packages.props` pour central package management
- [x] `.editorconfig` (naming, explicit types, sealed, CA2007/CA1848/CA1852 en error/warning)
- [x] `global.json` (SDK 10.0.104, rollForward latestFeature)
- [x] `.gitignore` .NET
- [x] `NuGet.config` (pin nuget.org, evite NU1507)
- [x] `LICENSE` (Apache 2.0)
- [x] `README.md` initial
- [x] `CHANGELOG.md` initial
- [x] `SECURITY.md`
- [x] `CONTRIBUTING.md`

### 1.2 Vellum.Abstractions
- [x] Interface `IKeyEncryptionProvider`
- [x] Interface `IEncryptionKeyStore` (scope on GetByIdAsync — M1)
- [x] Interface `IDekManager` (ValueTask on hot path — M7, scope on GetDekByKeyIdAsync — M1)
- [x] Interface `IPayloadEncryptor` (symmetric signatures — C4, IsEnabled — M10)
- [x] Interface `IRandomBytesProvider` (M3)
- [x] Record `EncryptionKey` (uses WrappedKey field — M9)
- [x] Record `Dek` (renamed from ActiveDek — M5)
- [x] Record `EncryptedPayload` (self-contained with WrappedDek — C3, binary Nonce/Ciphertext with structural equality — C4/L13)
- [x] Record `WrappedKey` (string ProviderVersion — N8/L14)
- [x] Static `PayloadEncryptorExtensions` — string convenience (C4)
- [x] XML docs sur tous les publics
- [x] Package metadata (authors, description, tags, repo url)
- [x] VersionPrefix=0.1.0 / VersionSuffix=preview.1 (C1)
- [x] Microsoft.SourceLink.GitHub reference + git init + origin remote (C2)
- [x] Build clean multi-target net8.0;net9.0;net10.0, zero warning avec TreatWarningsAsErrors=true
- [x] `tests/Vellum.Abstractions.Tests` — 5 smoke tests passent sur net8/9/10 (M8)

### 1.3 Vellum.Core
- [x] Porter `DekManager` depuis jacqcloud-buses (sealed partial, primary ctor, LoggerMessage source gen)
- [x] Generifier le scope (remplacer `Guid busId` par `string scope`)
- [x] Porter `PayloadEncryptor` (self-contained envelope, AES-256-GCM)
- [x] Adapter au nouveau `IKeyEncryptionProvider` abstrait
- [x] Options `VellumOptions` (DekCacheTtl, default 30 min)
- [x] Extension DI `AddVellum()` (TryAdd scoped lifetimes so EF Core store stays compatible)
- [x] Memory zeroing sur DEK apres usage (Encrypt + Decrypt + CreateDek race loser)
- [x] `ConfigureAwait(false)` partout
- [x] Extend `Dek` to carry its `WrappedKey` — decided option (b) to avoid a redundant store round-trip on the encrypt hot path
- [x] Cache-by-keyId key is scope-partitioned (`vellum:dek:id:{scope}:{keyId}`) — defense against cross-tenant cache poisoning (L15)
- [x] `ValueTask<Dek>` sync-cache-hit on `GetActiveDekAsync` and `GetDekByKeyIdAsync` (hot path allocation-free)
- [x] 4-layer race defense on `CreateDekAsync`: double-check + store-handles-uniqueness + winner-detection + unwrap-winner-if-race-lost-after-wrap
- [x] `tests/Vellum.Core.Tests` — 24 tests (DekManager 12, PayloadEncryptor 9, AddVellum 3) all green on net10.0 (net8/9 compile clean; host lacks net8/9 runtime)
- [x] `dotnet pack` produces Vellum.Core.0.1.0-preview.1.nupkg + snupkg (Source Link active via Directory.Build.props)

### 1.4 Vellum.Vault
- [x] Porter `VaultEncryptionService` depuis jacqcloud-buses (wrap/unwrap path uniquement, AES-GCM payload reste dans Vellum.Core.PayloadEncryptor)
- [x] Refactor en `VaultKeyEncryptionProvider : IKeyEncryptionProvider` (sealed partial, primary ctor, LoggerMessage)
- [x] Options `VaultOptions` (Address, Token, KeyName, HttpTimeout)
- [x] Validateur `IValidateOptions<VaultOptions>` + `ValidateOnStart()` — fail fast en config invalide
- [x] Extension DI `AddVaultProvider(Action<VaultOptions>)`
- [x] HttpClient typed (`AddHttpClient<VaultKeyEncryptionProvider>`), BaseAddress + Timeout + X-Vault-Token configurés
- [x] `IKeyEncryptionProvider` exposé via `TryAddTransient` (deviation du brief Singleton — voir L16, lifetime aligné sur la typed-client transient pour préserver la rotation des handlers)
- [x] DTOs records dans `Internal/` (Encrypt/Decrypt Request/Response/ResponseData) + `VaultJsonContext` source-gen pour JSON sans reflection
- [x] Parser robuste de la version `vault:v{N}:...` (ExtractProviderVersion — bornes explicites, pas IndexOf fragile)
- [x] `ProviderVersion` retourné verbatim au format `v{N}` pour préserver le sémantique Vault
- [x] Fail closed sur tous les paths d'erreur (HTTP non-2xx, JSON malformé, base64 malformé, ciphertext null/vide)
- [x] Token jamais loggé — vérifié dans tous les `[LoggerMessage]`
- [x] `tests/Vellum.Vault.Tests` — 30 tests verts sur net10.0 (Provider 22 + ServiceCollection 8)
- [x] `dotnet pack` produit Vellum.Vault.0.1.0-preview.1.nupkg (68K) + snupkg (72K) — Source Link actif
- [x] Build clean multi-target net8.0;net9.0;net10.0, 0 warning, 0 error

### 1.5 Vellum.Static (dev only)
- [x] `StaticKeyEncryptionProvider : IKeyEncryptionProvider` (sealed partial, LoggerMessage, startup warning Interlocked once-per-instance)
- [x] KEK depuis config via `StaticOptions.Base64Key` (AES-256 = 32 bytes)
- [x] Wrap format self-contained `static:v1:base64(nonce‖ciphertext‖tag)` — stateless unwrap
- [x] `StaticOptionsValidator : IValidateOptions<StaticOptions>` + `ValidateOnStart()` — rejette empty/invalid-base64/wrong-size sans jamais logger la clef
- [x] Extension DI `AddStaticProvider(Action<StaticOptions>)` — bridge Singleton (pas de HttpClient, L16 n'applique pas)
- [x] CA1716 (namespace "Static" = VB keyword) suppressed dans le csproj — accepté pour clarté du nom de package
- [x] CA1812 suppressed via `[SuppressMessage]` sur `StaticOptionsValidator` (DI-instantiated via `TryAddEnumerable` type-param overload)
- [x] WARNINGS massifs: `<Description>` NuGet, XML docs `⚠️ DEVELOPMENT USE ONLY ⚠️` sur class + extension, runtime WARNING log
- [x] Fail closed sur tous les paths: prefix invalide, base64 invalide, blob trop court, tag mismatch (AES-GCM), DEK vide, decoded key wrong length
- [x] `CryptographicOperations.ZeroMemory(kek)` dans `finally` pour wrap + unwrap
- [x] `tests/Vellum.Static.Tests` — 24 tests verts sur net10.0 (Provider 13 + ServiceCollection 11)
- [x] `dotnet pack` produit Vellum.Static.0.1.0-preview.1.nupkg (32K) + snupkg (30K) — Source Link actif, description contient ⚠️ DEVELOPMENT USE ONLY
- [x] Build clean multi-target net8.0;net9.0;net10.0, 0 warning, 0 error
- [x] Regression check: Phase 1.2 (5) + 1.3 (24) + 1.4 (30) + 1.5 (24) = **83/83 tests** verts sur net10.0

### 1.6 Vellum.InMemory
- [ ] `InMemoryEncryptionKeyStore` implementant `IEncryptionKeyStore`
- [ ] Thread-safe (ConcurrentDictionary)
- [ ] Extension DI `AddInMemoryStore()`

### 1.7 Vellum.EntityFrameworkCore
- [ ] Porter `BusEncryptionKeyRepository` depuis jacqcloud-buses
- [ ] Refactor en `EfCoreEncryptionKeyStore<TContext>`
- [ ] Entity `EncryptionKey` configurable (pas lie a un schema specifique)
- [ ] `IgnoreQueryFilters()` preserve
- [ ] Double-check + unique index pattern preserve (lecon v0.1.60-v0.1.63)
- [ ] Migrations EF Core (PostgreSQL + SQL Server + SQLite)
- [ ] Extension DI `AddEntityFrameworkCoreStore<TContext>()`

### 1.8 Tests
- [ ] `Vellum.Abstractions.Tests` (value objects, records)
- [ ] `Vellum.Core.Tests` (porter les tests DekManager + PayloadEncryptor)
- [ ] `Vellum.Vault.Tests` (porter VaultEncryptionServiceTests)
- [ ] `Vellum.Static.Tests`
- [ ] `Vellum.InMemory.Tests`
- [ ] `Vellum.EntityFrameworkCore.Tests` (TestContainers PostgreSQL)
- [ ] Tests de roundtrip encrypt/decrypt sur toutes les combinaisons provider + store
- [ ] Tests concurrents DEK creation (race conditions)

### 1.9 CI/CD
- [ ] GitHub Actions workflow (`build.yml`)
- [ ] Multi-target: net8.0, net9.0, net10.0
- [ ] Matrix OS: ubuntu, windows, macos
- [ ] `dotnet format --verify-no-changes`
- [ ] `dotnet test` avec coverage
- [ ] `dotnet pack` pour tous les packages
- [ ] Upload packages en artifacts
- [ ] Workflow `release.yml` declenche sur tag `v*`

### 1.10 Documentation
- [ ] README.md complet avec quickstart
- [ ] API docs genere depuis XML (DocFX ou similaire)
- [ ] Sample app `samples/Vellum.Sample.AspNetCore` (Vault + EF + docker-compose)
- [ ] Diagrammes architecture

---

## Phase 2 — Dogfood in Jacquouille

- [ ] Ajouter reference Vellum dans `jacqcloud-buses`
- [ ] Remplacer le code Encryption actuel par les packages Vellum
- [ ] Adapter `BusEncryptionKeyRepository` → implementer `IEncryptionKeyStore`
- [ ] Migration EF Core (renommer table si necessaire)
- [ ] Tests d'integration passent
- [ ] Benchmarks avant/apres (BenchmarkDotNet)
- [ ] 30 jours en production sans incident

---

## Phase 3 — Cloud providers

### Vellum.AzureKeyVault
- [ ] `AzureKeyVaultProvider` implementant `IKeyEncryptionProvider`
- [ ] Auth via `DefaultAzureCredential`
- [ ] Tests integration
- [ ] Docs

### Vellum.AwsKms
- [ ] `AwsKmsProvider` implementant `IKeyEncryptionProvider`
- [ ] Auth via AWS SDK default chain
- [ ] Tests integration (localstack)
- [ ] Docs

### Vellum.GcpKms
- [ ] `GcpKmsProvider` implementant `IKeyEncryptionProvider`
- [ ] Auth via Application Default Credentials
- [ ] Tests integration
- [ ] Docs

---

## Phase 4 — Rotation and hosting

### Vellum.Rotation
- [ ] `DekRotationHostedService` (porter depuis DekRotationBackgroundService)
- [ ] Options `RotationOptions` (Interval, ScopesToRotate)
- [ ] Extension DI `AddVellumRotation()`
- [ ] Tests

### Vellum.AspNetCore
- [ ] Extensions DI supplementaires
- [ ] Health checks (provider + store accessibles)
- [ ] `ActivitySource` pour OpenTelemetry tracing
- [ ] `Meter` pour metriques (counts, latencies, errors)

---

## Phase 5 — Hardening for 1.0

- [ ] `pg_advisory_xact_lock` pour DEK creation (DEK-LOCK backlog)
- [ ] Property-based tests (FsCheck) — roundtrip encrypt/decrypt
- [ ] Fuzzing harness sur input untrusted (nonce, ciphertext)
- [ ] Threat model document
- [ ] External crypto audit
- [ ] Benchmarks publics (BenchmarkDotNet)
- [ ] Migration guide depuis `Microsoft.AspNetCore.DataProtection`
- [ ] Migration guide depuis `AWS Encryption SDK`
- [ ] Sample apps par provider

---

## Release

- [ ] Reserver tous les noms NuGet (packages vides si besoin)
- [ ] Creer GitHub org (jacqcloud ou vellum-dotnet)
- [ ] `0.1.0-preview` sur NuGet
- [ ] Blog post annonce
- [ ] Audit crypto externe
- [ ] `1.0.0` GA
