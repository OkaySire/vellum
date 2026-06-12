# Changelog

All notable changes to Vellum will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-06-12

Remediation release driven by a full security + rotation review after the VPS
production incidents. Root cause of the outages: `RotateDekAsync` deactivated the
old DEK *before* wrapping the new one, with no transaction and no lock — a KEK
provider failure mid-rotation left scopes with zero active keys.

### Breaking

- **KEK rewrap tooling adds three interface members.** Consumers who implement these
  interfaces directly must implement the new members; all Vellum-shipped implementations
  are included:
  - `IKeyEncryptionProvider.RewrapAsync(WrappedKey, CancellationToken)` — re-encrypts a
    wrapped DEK under the provider's current KEK version without exposing the plaintext
    to the caller. `Vellum.Vault` uses Transit's native `POST /v1/transit/rewrap/{key}`
    (plaintext never leaves Vault); `Vellum.Static` unwraps/rewraps internally and zeroes
    the intermediate plaintext (dev-only provider).
  - `IEncryptionKeyStore.UpdateWrappedKeyAsync(Guid keyId, string scope, WrappedKey,
    CancellationToken)` — replaces the wrapped material of an existing key (active or
    historical), scope-checked (M1), fail-closed (`InvalidOperationException` on missing
    key or scope mismatch — never a silent no-op). KeyId/Scope/CreatedAt/ExpiresAt/IsActive
    are immutable; only the wrapped material and provider version change.
  - `IPayloadEncryptor.RewrapPayloadAsync(EncryptedPayload, CancellationToken)` — returns
    a copy of the envelope with the embedded `WrappedDek` rewrapped; ciphertext, nonce,
    key id, and format version are carried over verbatim (the DEK plaintext is untouched,
    so the AES-GCM payload stays valid).
- **`PayloadEncryptor` constructor gains an `IKeyEncryptionProvider` parameter** (second
  position) to back `RewrapPayloadAsync`. Consumers who construct `PayloadEncryptor` by
  hand (rare — normally the DI container does it) must pass the provider.
- **`IEncryptionKeyStore` gains `RotateAsync(EncryptionKey newKey, CancellationToken)`.**
  Atomically deactivates all active keys for the new key's scope *and* inserts the
  new active key in a single transaction. On failure nothing changes — the old key
  stays active. Consumers who implement `IEncryptionKeyStore` directly must
  implement the new member; `Vellum.EntityFrameworkCore` and `Vellum.InMemory`
  ship implementations.
- **`EncryptedPayload` gains a `FormatVersion` field** (5th positional parameter,
  default `CurrentFormatVersion = 1`). Existing 4-argument construction still
  compiles and defaults to v1, so persisted pre-0.2.0 envelopes decrypt unchanged.
  The version is stamped at encrypt and validated fail-closed at decrypt: an
  unknown version throws `CryptographicException` *before* any KEK round-trip.
  Consumers persisting envelopes field-by-field should persist `FormatVersion` too.
- **Plain `http://` Vault addresses are rejected by default.** Over plain HTTP the
  `X-Vault-Token` header and the base64 plaintext DEKs travel in cleartext. Local
  development against `vault server -dev` must now opt in explicitly via
  `VaultOptions.AllowInsecureHttp = true` (logged as a warning on every client
  construction).

### Fixed

- **Atomic, fail-safe DEK rotation.** `DekManager.RotateDekAsync` now generates and
  wraps the new DEK *before* touching anything, then swaps the active key via the
  new `IEncryptionKeyStore.RotateAsync` in one transaction, then replaces (never
  removes) the cache entry. If Vault or the store fails at any point, the old key
  remains active *and* cached — the scope is never observed without an active DEK.
- **Per-scope async lock in `DekManager`** (`SemaphoreSlim` per scope, cache-hit
  fast path stays lock-free) eliminates three races at once: the cache re-poisoning
  race where an in-flight slow read re-cached a freshly-deactivated DEK after a
  rotation, the KEK-provider stampede where N concurrent cache misses each
  round-tripped to Vault, and the spurious "no concurrent winner" errors from
  create-vs-rotate interleavings.
- **`EnsureDekLength` on race-loss paths.** The winner's unwrapped DEK is now
  length-checked (32 bytes, AES-256) on both the create and rotate race-loss
  reconciliation paths, symmetric with every other unwrap path.
- **Encrypt-side DEK length guard.** `PayloadEncryptor` rejects DEKs that are not
  32 bytes before encrypting, so a buggy or compromised KEK provider cannot
  silently downgrade payloads to AES-128/192.

### Security

- **Vault token redaction in `HttpClientFactory` logs.** The `X-Vault-Token` header
  is redacted unconditionally via `RedactLoggedHeaders` on all three TFMs.
- **Bounded Vault error-body buffering.** `MaxResponseContentBufferSize` = 64 KB on
  the typed Vault client; an oversized response body fails closed with
  `HttpRequestException` instead of buffering unbounded attacker-controlled bytes.

### Added

- **KEK rewrap tooling** — the missing piece that makes retiring old KEK versions
  (Vault Transit `min_decryption_version`) safe:
  - `VellumRewrapService.RewrapStoredKeysAsync(scope)` (registered by `AddVellum()`,
    scoped) sweeps every stored key for a scope — active *and* historical, deduplicated
    by key id — rewraps each via the KEK provider and persists the refreshed material.
    Per-key failure isolation: one key failing never aborts the sweep; failures are
    logged and returned in `RewrapScopeResult(Total, Rewrapped, Failed, FailedKeyIds)`
    so the (idempotent) sweep can be re-run until `Failed == 0`.
  - `IPayloadEncryptor.RewrapPayloadAsync(payload)` rewraps the wrapped DEK embedded in
    a persisted envelope; consumers iterate their own payload storage and persist the
    returned copy. The decrypt cache needs no invalidation: entries are keyed by a
    SHA-256 of the wrapped ciphertext, so a rewrapped envelope gets a fresh cache key
    while the old envelope's entry simply ages out (L24).
  - `docs/kek-rotation.md` now documents the **safe `min_decryption_version` procedure**
    (rotate → rewrap stored keys → rewrap envelopes → verify → bump) instead of a
    blanket "never bump" rule.
- **`Vellum.Rotation` package** — opt-in background DEK rotation hosted service.
  `AddVellumRotation(Action<RotationOptions>?)` registers a worker that ticks every
  `RotationInterval` (default 24 h), rotates only scopes whose active key is older
  than `MaxDekAge` (default 24 h — no unconditional rotation, no synchronized
  churn), and retries failed scopes with exponential backoff + jitter *within* the
  tick (`MaxRetriesPerScope`, default 3; `RetryBaseDelay`, default 5 s) so a Vault
  blip does not postpone a rotation by a full interval. One scope failing never
  aborts the others, and a `StartupDelay` (default 1 min) keeps the worker from
  hammering the KEK provider at boot. Options validated via `ValidateOnStart()`.
- **`docs/kek-rotation.md`** — operational runbook: DEK vs KEK rotation, why Vault
  Transit KEK rotation is safe by default, the fail-safe Vault-down behaviour, and
  the **`min_decryption_version` hazard** (every persisted envelope embeds its own
  wrapped DEK; bumping the minimum above any persisted version makes those payloads
  permanently undecryptable — only safe after the full rewrap procedure above).

### Tests

207 → 332 tests per TFM (996 across net8.0/net9.0/net10.0), all green.
Per-project breakdown (per TFM): `Abstractions 9`, `Core 83`, `EntityFrameworkCore 42`,
`Static 28`, `InMemory 43`, `Vault 97`, `Rotation 30` (new).

## [0.1.0] — 2026-04-13

### Stabilized

- **First non-preview release.** Graduates from preview after 4 iterations of consumer dogfood (jacqcloud-buses, 3 migration cycles) and 1 production hotfix. No code changes from `0.1.0-preview.4` — this release only flips the version suffix. The API is considered usable for non-critical production workloads.
- **Pre-1.0 disclaimer**: Semver 0.x.y allows breaking changes in minor versions. Expect potentially breaking API evolution in `0.2.0` (fluent API, rotation package) and `0.3.0` (cloud KMS providers). A stable `1.0` is planned after the external crypto audit + cloud provider completion.

### Upcoming in 0.2.0

- Vellum.Rotation package (background DEK rotation hosted service)
- Vellum.AspNetCore package (health checks, OpenTelemetry)
- VellumBuilder fluent API for discoverability
- SchemaVersion on EF entity for future migration support

### Upcoming in 0.3.0

- Vellum.AzureKeyVault (Azure Key Vault KEK provider)
- Vellum.AwsKms (AWS KMS KEK provider)
- Vellum.GcpKms (Google Cloud KMS KEK provider)

## [0.1.0-preview.4] — 2026-04-12

### Fixed
- **PRODUCTION HOTFIX**: `DekManager` cache entries now specify `Size = 1` in `MemoryCacheEntryOptions`. Previously, consumers who configured `IMemoryCache` with a `SizeLimit` (standard in production for memory budgets) would get `InvalidOperationException: Cache entry must specify a value for Size when SizeLimit is set` on every encrypt/decrypt operation. ([L25](tasks/lessons.md))

### Tests

163 → 166 tests (net10.0 run), all green. Per-project breakdown:
`Abstractions 7`, `Core 41` (+3), `EntityFrameworkCore 29`,
`Static 24`, `InMemory 30`, `Vault 35`.

## [0.1.0-preview.3] — 2026-04-11

Targeted follow-up to `0.1.0-preview.2` that closes the single dogfood friction
backend surfaced while trying to adopt the snake_case column-name overrides from
`#8`. No new features, one issue closed, one attribute added.

### Added

- **#17 — `[VellumEntityFrameworkOptions]` attribute on the `DbContext` class.**
  `dotnet ef migrations add` prefers an `IDesignTimeDbContextFactory<T>` over the
  host-build path when both are available. A factory that only calls `UseNpgsql`
  (or any other provider extension) without `UseVellum` ships `DbContextOptions`
  that do not carry the Vellum options extension, and the scaffolder silently
  falls back to Vellum defaults (PascalCase column names, SQL Server filter
  syntax) even when the runtime `AddDbContext` pipeline is configured correctly.
  `jacqcloud-buses` iteration 2 hit this while trying to rename the Vellum
  columns to `snake_case` and had to defer the rename.

  The fix is a declarative, per-`DbContext` source of options that is
  reflection-readable at both runtime and design time: decorate the context class
  with `[VellumEntityFrameworkOptions(TableName = "…", KeyIdColumnName = "…", …)]`
  and `VellumModelBuilderExtensions.ResolveOptions` picks the attribute up as
  priority 2 (between the explicit `UseVellum` extension and the
  `IOptions<VellumEntityFrameworkOptions>` application-services fallback). Every
  attribute property the consumer leaves unset keeps the built-in default, so a
  minimal decoration like `[VellumEntityFrameworkOptions(TableName =
  "bus_encryption_keys")]` is valid.

  An `IDesignTimeDbContextFactory<T>` that calls `UseVellum` explicitly still
  works; the attribute is the recommended path when the schema is fixed at
  compile time and the consumer wants a single source of truth. See
  `README.md#design-time-scaffolder-dotnet-ef-migrations-add` for the full
  pattern.

### Tests

161 → 163 tests (net10.0 run), all green. Per-project breakdown:
`Abstractions 7`, `Core 38`, `EntityFrameworkCore 29` (+2),
`Static 24`, `InMemory 30`, `Vault 35`.

### Notes

- Audit posture unchanged: 0 critical / 0 high / 0 medium / 0 low open.
- CodeQL posture unchanged: 0 open alerts.
- No breaking changes. Existing `UseVellum`, `AddEntityFrameworkCoreStore<T>`,
  and `AddVellumEncryptionKeys(this)` call sites keep working unchanged — the
  attribute is strictly additive and slots in between the existing priority
  levels.

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

[Unreleased]: https://github.com/OkaySire/vellum/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/OkaySire/vellum/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/OkaySire/vellum/compare/v0.1.0-preview.4...v0.1.0
[0.1.0-preview.4]: https://github.com/OkaySire/vellum/compare/v0.1.0-preview.3...v0.1.0-preview.4
[0.1.0-preview.3]: https://github.com/OkaySire/vellum/compare/v0.1.0-preview.2...v0.1.0-preview.3
[0.1.0-preview.2]: https://github.com/OkaySire/vellum/compare/v0.1.0-preview.1...v0.1.0-preview.2
[0.1.0-preview.1]: https://github.com/OkaySire/vellum/releases/tag/v0.1.0-preview.1
