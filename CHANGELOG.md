# Changelog

All notable changes to Vellum will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-preview.2] — 2026-04-11

Feedback release driven by the `jacqcloud-buses` Phase 2 dogfood. Backend migrated
from a hand-rolled encryption layer to Vellum 0.1.0-preview.1 and filed a 262-line
feedback report plus 10 labelled issues. This release closes the 7 that were
scoped to `0.1.0-preview.2` — 6 UX frictions plus 1 critical performance fix.

### Added

- **#6 — Built-in DEK cache on the decrypt path.**
  `IDekManager.GetDekByWrappedKeyAsync(WrappedKey)` unwraps once, caches the
  plaintext DEK keyed on a SHA-256 hash of the wrapped ciphertext, and routes
  `PayloadEncryptor.DecryptAsync` through the cache. Read-heavy workloads now pay
  at most one KEK round-trip per distinct DEK instead of one per decrypt.
  Cache-hit is synchronous (`ValueTask`) and allocation-free aside from the DEK
  clone required by lesson L3.
  See the private lesson L24 for why the wrapped-ciphertext hash does not require
  scope partitioning (it is the tenant-specific secret material itself, not a
  guessable opaque identifier).
- **#8 — Column-name overrides on `VellumEntityFrameworkOptions`.**
  Seven new properties (`KeyIdColumnName`, `ScopeColumnName`,
  `WrappedCiphertextColumnName`, `WrappedProviderVersionColumnName`,
  `CreatedAtColumnName`, `ExpiresAtColumnName`, `IsActiveColumnName`) let
  consumers rename every mapped column to match an existing snake_case schema.
  Defaults stay PascalCase for backward compatibility. The validator rejects
  empty/whitespace column names at host start.
- **#9 — `DbContextOptionsBuilder.UseVellum(...)` for single-source options.**
  Consumers attach `VellumEntityFrameworkOptions` directly to the
  `DbContextOptionsBuilder` that feeds `AddDbContext<T>`, and the new
  `modelBuilder.AddVellumEncryptionKeys(this)` signature reads them back inside
  `OnModelCreating` via a new internal `VellumDbContextOptionsExtension`. Falls
  back to `IOptions<VellumEntityFrameworkOptions>` resolved from
  `CoreOptionsExtension.ApplicationServiceProvider` for consumers who prefer the
  DI-first path via `AddEntityFrameworkCoreStore<T>(configure)`. The literal
  overload `AddVellumEncryptionKeys(ModelBuilder, VellumEntityFrameworkOptions)`
  remains as an escape hatch for design-time tooling and tests.
- **#7 — README quickstart.** The 30-ish-line snippet in `README.md`
  shows `AddVellum + AddVaultProvider + AddDbContext<T>(UseVellum) +
  AddEntityFrameworkCoreStore<T> + modelBuilder.AddVellumEncryptionKeys(this)`
  using the preview.2 API.
- **#10 — `samples/` folder with 5 canonical entries.**
  - `samples/Console.Static` — runnable 20-line Hello World using
    `Vellum.Static` + `Vellum.InMemory`.
  - `samples/AspNetCore.Postgres.Vault` — full ASP.NET Core minimal API +
    Npgsql + HashiCorp Vault Transit, with `docker-compose.yml` for local
    containers.
  - `samples/FeatureFlagged` — `IPayloadEncryptor` decorator gated on
    `IOptionsMonitor<FeatureFlags>`, with sentinel-passthrough semantics for
    staged rollouts.
  - `samples/MigrationFromCustom` — recipe (README only) documenting the exact
    EF Core migration rewrite used by the `jacqcloud-buses` v0.1.63 → Vellum
    migration, including the `'v<N>'` format gotcha their integration suite
    caught.
  - `samples/CachingDecrypt` — tombstone README explaining that this pattern
    became obsolete in preview.2 once #6 shipped.
- **#11 — Documented feature-flagged encryption wrapper pattern.**
  Reference implementation in `samples/FeatureFlagged`, with notes on Scrutor's
  `services.Decorate<>` for real DI wiring and a discussion of the
  passthrough-sentinel vs throw-on-disabled trade-off.
- **#12 — Documented consumer-options → Vellum-options deferred config pattern.**
  New `docs/consumer-options-bridging.md` shows the working
  `AddOptions<VellumOptions>().Configure<IOptions<EncryptionOptions>>(...)` flow
  the backend team discovered, along with the
  `AddDbContext<T>((sp, opts) => ...)` variant for `UseVellum`.

### Changed

- **Breaking — `PayloadEncryptor` constructor.** The `IKeyEncryptionProvider`
  parameter has been removed. Decrypt now routes through
  `IDekManager.GetDekByWrappedKeyAsync` instead of calling the KEK provider
  directly, so `PayloadEncryptor` no longer depends on `IKeyEncryptionProvider`
  at all. Consumers who construct `PayloadEncryptor` by hand (rare — normally
  the DI container does it) must drop the `IKeyEncryptionProvider` argument.
- **Breaking — `IDekManager` interface.** Gains a new method
  `GetDekByWrappedKeyAsync(WrappedKey, CancellationToken)`. Consumers who
  implement `IDekManager` directly (rare) must implement the new method.
- **Breaking — `AddVellumEncryptionKeys` signature.** The canonical overload is
  now `AddVellumEncryptionKeys(this ModelBuilder, DbContext context)` which
  reads options from DI. The legacy
  `AddVellumEncryptionKeys(ModelBuilder, VellumEntityFrameworkOptions)` overload
  remains available for design-time tooling and tests.

### Tests

150 → 161 tests (net10.0 run), all green. Per-project breakdown:
`Abstractions 7`, `Core 38` (+7), `EntityFrameworkCore 27` (+4),
`Static 24`, `InMemory 30`, `Vault 35`.

### Notes

- Audit posture unchanged: 0 critical / 0 high / 0 medium / 0 low open.
- CodeQL posture unchanged: 0 open alerts.
- Backend's dogfood was the source of the zero-surprise finding that caught the
  `'v<N>'` format drift in their own migration path; see
  `samples/MigrationFromCustom/README.md` for the recipe and the exact assertion
  (`~ '^v[0-9]+$'`) that fired.

## [0.1.0-preview.1] — 2026-04-10

First public preview published to nuget.org. Phase 1 scaffold + `Vellum.Abstractions`
+ `Vellum.Core` + `Vellum.Vault` + `Vellum.Static` + `Vellum.InMemory` +
`Vellum.EntityFrameworkCore`. Not for production.

- Initial solution layout, `Directory.Build.props`, `Directory.Packages.props`,
  `.editorconfig`, Apache 2.0 license.
- `Vellum.Abstractions` package with core interfaces (`IKeyEncryptionProvider`,
  `IEncryptionKeyStore`, `IDekManager`, `IPayloadEncryptor`) and value objects
  (`EncryptionKey`, `Dek`, `EncryptedPayload`, `WrappedKey`).
- `Vellum.Core` with `DekManager` + `PayloadEncryptor` + AES-GCM via
  `System.Security.Cryptography`.
- `Vellum.Vault` HashiCorp Vault Transit KEK provider.
- `Vellum.EntityFrameworkCore` + `Vellum.InMemory` stores.
- 150 tests green on net10.0 (compile-only on net8.0 / net9.0).
- Audit remediation: 3 High, 7 Medium, 9 Low actionable findings fixed.

[Unreleased]: https://github.com/OkaySire/vellum/compare/v0.1.0-preview.2...HEAD
[0.1.0-preview.2]: https://github.com/OkaySire/vellum/compare/v0.1.0-preview.1...v0.1.0-preview.2
[0.1.0-preview.1]: https://github.com/OkaySire/vellum/releases/tag/v0.1.0-preview.1
