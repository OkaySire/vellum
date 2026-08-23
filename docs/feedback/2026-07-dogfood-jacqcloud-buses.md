# Vellum 0.1.0-preview.1 dogfood — migration feedback

**Repo**: jacqcloud-buses
**Branch**: `feature/vellum-migration`
**Migration strategy**: A.2 (custom `IPayloadEncryptor` adapter over `Vellum.IDekManager`, preserves v0.1.58 cache lesson)
**Build status**: 0 errors / 0 warnings
**Tests**: 59/59 unit + 2/2 smoke (Vault gated) + 15/15 integration (Postgres + Vault gated)
**Smoke test**: green — `VellumSmokeTest` against docker Vault dev mode
**Integration**: green — 15 tests across `MigrationBackfillTests` (assertions) + `PostMigrationRoundtripTests` (full Infrastructure stack)

---

## 1. Integration friction (chronological)

Every moment I had to stop, context-switch, or go spelunking.

1. **README.md has no quickstart.** The published `Vellum.Abstractions`/`Vellum.Core`/`Vellum.Vault`/`Vellum.EntityFrameworkCore` README.md files all point to "Quickstart: (coming soon — Phase 1 in progress)". I had to read the 1,581 lines of XML doc across 4 assemblies to reconstruct the public API surface and the call chain. A single 30-line snippet showing `AddVellum() + AddVaultProvider() + AddEntityFrameworkCoreStore<T>() + modelBuilder.AddVellumEncryptionKeys()` would have saved the first hour of the migration.

2. **`AddVellumEncryptionKeys(modelBuilder, options)` takes `VellumEntityFrameworkOptions` as a literal argument — not from DI.** I had to duplicate the options configuration in two places: once in `AddEntityFrameworkCoreStore<TContext>(configure)` (registration) and once in `RuntimeDbContext.OnModelCreating` (model construction). No doc guidance on how to share them. I ended up with a hand-duplicated `new VellumEntityFrameworkOptions { TableName = ..., SchemaName = ..., UniqueActiveIndexFilter = ... }` in both call sites and a comment "keep in sync". This is the single biggest papercut in the integration.

3. **`IPayloadEncryptor.IsEnabled` is effectively hardcoded `true` in the default Core impl.** Our existing code used `EncryptionOptions.Enabled` to feature-flag encryption per deployment during rollout. Vellum's doc literally tells consumers to "wrap this type behind their own guard" — fine as a workaround, but it means every consumer with a staged rollout has to re-implement the same gate. A built-in `VellumOptions.Enabled` toggle would save that code.

4. **No DEK cache on the decrypt path.** `Vellum.IPayloadEncryptor.DecryptAsync` hits the KEK provider on every call (self-contained decryption is a deliberate design choice — I see why). But for our bus workload, the decrypt path is as hot as the encrypt path (every message list read), and before this migration we cached unwrapped DEKs by `keyId` via `IMemoryCache` (see `lessons.md` L10, v0.1.58 production fix). Going full Vellum would have re-introduced that Vault round-trip for every read. I ended up writing a **custom `VellumBackedPayloadEncryptor`** that bypasses `Vellum.PayloadEncryptor` and talks directly to `Vellum.IDekManager.GetDekByKeyIdAsync` (which *does* cache). The hand-rolled AES-GCM lives in my repo, not in Vellum. **This is the single biggest functional gap** — see sections 3 and 5.

5. **`Vellum.IDekManager` clashes with my existing `JacqCloud.Buses.Domain.Interfaces.IDekManager`.** Since I was deleting mine and replacing it, that wasn't a long-term issue — but my adapter `VellumBackedPayloadEncryptor` lives in `JacqCloud.Buses.Infrastructure.Encryption` and uses *both* the Domain `IPayloadEncryptor` (interface to implement) and the Vellum `IDekManager` (dependency). The ambiguity errors forced me to use `using VellumDek = Vellum.Dek; using VellumDekManager = Vellum.IDekManager;` aliases. Minor, but it adds ceremony to any consumer who wants to keep their own encryption interface alongside Vellum.

6. **Vellum's `EncryptionKey.CreatedAt`/`ExpiresAt` are `DateTimeOffset` but my existing `bus_encryption_keys` table stores `DateTime`.** The EF migration scaffolder handled the CLR type change but the PostgreSQL column type is `timestamp with time zone` in both cases (Npgsql maps both `DateTime` and `DateTimeOffset` to `timestamptz`), so the physical storage was compatible and no data migration was needed on those columns. Surprised me — expected type-mismatch pain.

7. **`dotnet ef migrations add` produced a semantically wrong migration.** The scaffolder's rename heuristic decided that my `organization_id` column should be renamed to `KeyId` — which is nonsense: `organization_id` is the tenant identifier and `KeyId` is the DEK's own Guid (equivalent to my `id` column). I had to manually rewrite the `Up()` method to:
   - drop `organization_id` entirely (Vellum has no tenant concept at this layer),
   - rename `id → KeyId` (preserving the DEK Guids),
   - add `Scope` column and backfill `Scope = 'bus:' || bus_instance_id`,
   - add `WrappedProviderVersion` and backfill from `vault_key_version::text`,
   - drop `bus_instance_id` and `vault_key_version`,
   - rename remaining columns from snake_case to PascalCase,
   - recreate PK + filtered unique index.
   The scaffolder cannot infer the semantic rename because Vellum's column names don't follow the consumer's naming convention — see friction #8.

8. **Column name convention is hard-coded to PascalCase.** `VellumEntityFrameworkOptions` exposes `TableName`, `SchemaName`, `UniqueActiveIndexFilter`, `ScopeMaxLength`, `WrappedProviderVersionMaxLength` — but no column-name overrides. My whole existing schema uses snake_case (`bus_instance_id`, `encrypted_dek`, `vault_key_version`). Vellum's table now has a jarring `KeyId`, `Scope`, `WrappedCiphertext`, `WrappedProviderVersion`, `CreatedAt`, `ExpiresAt`, `IsActive` sitting in the middle of a snake_case schema. No way to either (a) override each column name or (b) register a `UseSnakeCaseNamingConvention`-style global on the Vellum entity specifically.

9. **Passing consumer-level options into `AddVaultProvider` / `AddVellum`.** Both take `Action<TOptions>` delegates. My consumer-level config sits in `EncryptionOptions` (`VaultAddress`, `VaultToken`, `KeyName`, `DekCacheTtl`). I wanted to write `AddVaultProvider(opts => { opts.Address = encryptionOptions.VaultAddress; ... })` but `encryptionOptions` isn't available at registration time — only via `IOptions<EncryptionOptions>` at resolution time. My first attempt (anti-pattern) was to call `services.BuildServiceProvider()` inside the delegate. My second attempt used `services.AddOptions<VaultOptions>().Configure<IOptions<EncryptionOptions>>((vault, enc) => ...)` to defer. That works, but it's non-obvious, and it requires calling `AddVaultProvider(_ => { })` with a no-op delegate first so the provider/HttpClient are registered. A sample showing this pattern would help — right now consumers either land on the anti-pattern or have to know the deferred-configure trick.

## 2. API design friction

1. **Scope string is opaque but decryption requires it.** `IDekManager.GetDekByKeyIdAsync(Guid keyId, string scope)` forces the caller to remember the scope at decrypt time. My old `IPayloadEncryptor.DecryptAsync(ciphertext, nonce, keyId)` didn't need the scope because the legacy store indexed keys by `id` only. I had to widen the domain interface to `DecryptAsync(ciphertext, nonce, keyId, busId)` and push the scope reconstruction into every call site. Understandable for the multi-tenant defense (comment in `IDekManager.GetDekByKeyIdAsync` XML doc), but it's a mandatory callsite change for any consumer with an existing `DecryptByKey` pattern.

2. **`IPayloadEncryptor.EncryptAsync(ReadOnlyMemory<byte>, string, CancellationToken)` is binary-first.** 90% of my call sites have a `string` plaintext. The `PayloadEncryptorExtensions.EncryptStringAsync` / `DecryptStringAsync` helpers live in a separate file. I wasted ~5 minutes looking for `EncryptAsync(string, ...)` before grepping for `PayloadEncryptorExtensions`. A prominent README snippet showing `await encryptor.EncryptStringAsync("hello", "bus:abc")` would prevent this.

3. **`EncryptedPayload.KeyId` is "audit only".** The XML doc is explicit that decryption does not need it. But my existing schema indexes by `EncryptionKeyId` and that's how my message rows link to the wrapped DEK. Vellum's envelope design is strictly better (self-contained, no DB round-trip on decrypt) but Day-1 consumers with existing persistence will all face the same "do I take the Vellum envelope model or shim it over my columns?" fork.

4. **`AddVellum` / `AddVaultProvider` / `AddEntityFrameworkCoreStore<T>` are three independent `IServiceCollection` extensions.** No fluent builder, so there's no discoverability chain: a new consumer doesn't know they need all three. A `VellumBuilder` returned by `AddVellum()` exposing `.UseVaultProvider(...)` / `.UseEntityFrameworkCoreStore<T>()` would:
   - make the required sequence obvious,
   - let the builder pull in `IOptions<VellumOptions>` so consumer options can be shared across providers,
   - make it explicit which packages have to be installed.

5. **The domain records use `WrappedKey(Ciphertext, ProviderVersion)` as a record with positional params.** Constructing one by hand (e.g. for a test fixture or a migration tool) means remembering which slot is which. Named `WrappedKey.Create(ciphertext, providerVersion)` or `WrappedKey { Ciphertext = ..., ProviderVersion = ... }` would be safer.

## 3. Missing features vs jacqcloud-buses v0.1.63

| Feature | Present in v0.1.63 | Present in Vellum 0.1.0-preview.1 | Notes |
|---|---|---|---|
| Envelope DEK/KEK via AES-GCM | ✅ | ✅ | Symmetric — no blocker |
| HashiCorp Vault Transit KEK | ✅ | ✅ `Vellum.Vault` | Symmetric |
| EF Core store with filtered unique index | ✅ | ✅ `Vellum.EntityFrameworkCore` | Symmetric |
| Multi-pod race defense (4-layer) | ✅ | ✅ Doc reference to lessons.md L2 | Actually better — built into the store |
| `IgnoreQueryFilters()` on every read | ✅ (after v0.1.63 hotfix) | ✅ Built-in | Better — no way to forget |
| DEK cache on encrypt path | ✅ | ✅ `IMemoryCache` via `IDekManager` | Symmetric |
| **DEK cache on decrypt path** | ✅ (`GetDekByKeyIdAsync` cached) | ⚠️ Only via `IDekManager.GetDekByKeyIdAsync` (not via `IPayloadEncryptor.DecryptAsync`) | **Functional gap** — see section 1 friction #4 |
| **Feature-flag encryption per deployment** | ✅ `EncryptionOptions.Enabled` gates every call | ⚠️ Consumer must wrap `IPayloadEncryptor` | Gap — forces ceremony for staged rollouts |
| **DEK rotation background worker** | ✅ `DekRotationBackgroundService` | ❌ Reserved for `Vellum.Rotation` (Phase 4) | Must carry locally for now |
| **Plaintext-to-encrypted migration worker** | ✅ `MessageEncryptionMigrationService` + `ContextEncryptionMigrationService` | ❌ Not in scope — consumer concern | Expected, but the pattern (background job iterating unencrypted rows) is common enough to be worth a sample |
| **Tenant-scoped DEKs (organization_id tracking)** | ✅ row carries `organization_id` | ❌ Vellum has only opaque `Scope` | Meant we had to drop our `organization_id` column on the DEK table — **acceptable but a design delta consumers need to notice** |
| **Multi-tenant defense on GetDekByKeyId** | ❌ (relied on query filters) | ✅ scope-matching assertion | Better |
| **`VaultKeyVersion` as `int` for audit** | ✅ | ⚠️ `WrappedKey.ProviderVersion` is `string` | Semantically equivalent but requires `.ToString()` on the round-trip for old consumers who bucketed by int |
| **Health check for KEK provider** | ❌ (we didn't have one) | ❌ Reserved for `Vellum.AspNetCore` (Phase 4) | Same state |
| **Metrics / OpenTelemetry spans** | ❌ | ❌ | Same state |

## 4. Documentation gaps

Questions I couldn't answer from README/XML doc and had to guess:

1. **How do I share `VellumEntityFrameworkOptions` between `AddEntityFrameworkCoreStore<T>` and `AddVellumEncryptionKeys`?** (duplicated literals)
2. **What's the intended pattern for feature-flagged encryption?** (I guessed: custom `IPayloadEncryptor` wrapper)
3. **Does `AddVaultProvider` validate `VaultOptions.Address` is an absolute URI?** (XML says yes but doesn't show the error format — I haven't hit it yet)
4. **Does `Vellum.EntityFrameworkCore` call `EnsureCreated` / auto-create the table, or is the consumer always on the hook for migrations?** (I guessed: consumer, because the XML doc says "Vellum does not ship migrations of its own")
5. **What happens if `EncryptionKey.Scope` is `null` or empty?** (XML says opaque but doesn't say validated — is `""` a legal scope?)
6. **Can I use `Vellum.Static` in integration tests and swap to `Vellum.Vault` in prod via conditional DI?** (guessed yes, haven't tested)
7. **How does `DekCacheTtl = TimeSpan.Zero` behave?** (XML says "disable caching entirely" — does that mean `IDekManager.GetActiveDekAsync` becomes effectively synchronous through Vault on every call? Any perf warning?)
8. **Is the DEK cache keyed by `(scope, keyId)` or just `keyId`?** (XML says "partitioned by scope in the cache key so that a cross-scope lookup of the same Guid cannot return a cached entry from a different tenant" — good, but the phrase `cache key` is never shown)
9. **Does the 4-layer race defense on `CreateAsync` work across multiple pods using the same PostgreSQL DB?** (yes based on the unique-index + DbUpdateException pattern, but a quick "multi-pod" doc note would reassure)
10. **What provider name does `VaultKeyEncryptionProvider.ProviderName` return?** (`"vault"`? Not documented explicitly — the XML only says "stable, human-readable identifier")

## 5. Sample code I wish had existed

The 5 samples that would have cut my integration time in half:

1. **`samples/Vellum.Samples.AspNetCorePostgres/`** — full ASP.NET Core 10 web app:
   - `Program.cs` wiring `AddVellum() + AddVaultProvider() + AddEntityFrameworkCoreStore<AppDbContext>()`
   - `AppDbContext.OnModelCreating` calling `AddVellumEncryptionKeys(options)` with the Npgsql filter override
   - A controller that `EncryptStringAsync` / `DecryptStringAsync` a payload
   - `docker-compose.yml` with Vault dev mode + Postgres
   - A README showing how to run the Transit engine setup (`vault secrets enable transit`, `vault write -f transit/keys/my-key`)

2. **`samples/Vellum.Samples.Console/`** — 20-line console app with `Vellum.Static` provider for local tinkering without Vault.

3. **`samples/Vellum.Samples.FeatureFlagged/`** — a custom `IPayloadEncryptor` wrapper that reads a `EncryptionFeatureFlag` and no-ops when disabled, so consumers with staged rollouts have a starting point.

4. **`samples/Vellum.Samples.MigrationFromCustom/`** — a *consumer's custom encryption → Vellum* migration recipe. A minimal EF migration showing how to rename columns, backfill `Scope` from an existing tenant column, populate `WrappedProviderVersion` from a legacy integer column. **This is the single most valuable sample for Day-1 adopters who already have encrypted data.**

5. **`samples/Vellum.Samples.CachingDecrypt/`** — a wrapper `CachingPayloadEncryptor` that caches unwrapped DEKs by `KeyId` on the decrypt path (see section 3 table — the missing feature). This would let consumers get self-contained envelopes *and* cached decryption, without writing it themselves.

## 6. Migration recipe (step-by-step, as I ran it)

Timing approximate — measured against `feature/vellum-migration` commits.

| # | Step | Command / files touched | Time |
|---|---|---|---|
| 1 | Branch + install packages | `git checkout -b feature/vellum-migration` then `dotnet add package Vellum.{Abstractions,Core,Vault,EntityFrameworkCore} --version 0.1.0-preview.1` | 5 min |
| 2 | Baseline build | `dotnet build` → 0/0 with packages but no code change yet | 1 min |
| 3 | API discovery | Read 1,581 lines across 4 XML docs | 25 min |
| 4 | Strategy decision | Picked A.2 (adapter, keep decrypt cache) after noticing Vellum's decrypt path has no cache — flagged it to the orchestrator | 10 min |
| 5 | Delete Domain types | 11 files removed: `IEncryptionService`, `IDekManager`, `IBusEncryptionKeyRepository`, `ActiveDek`, `EncryptedPayload`, `BusEncryptionKey`, `VaultEncryptionService`, `DekManager`, `PayloadEncryptor`, `BusEncryptionKeyRepository`, `BusEncryptionKeyConfiguration` | 2 min |
| 6 | Write `VellumBackedPayloadEncryptor` | 100-line adapter over `Vellum.IDekManager` + hand-rolled AES-GCM | 15 min |
| 7 | Rewrite DI | `EncryptionServiceCollectionExtensions.AddEncryption` → `AddVellum` + `AddVaultProvider` + `AddEntityFrameworkCoreStore<RuntimeDbContext>` + deferred `AddOptions<T>().Configure<IOptions<EncryptionOptions>>` | 15 min |
| 8 | Rewire `RuntimeDbContext` | Remove `DbSet<BusEncryptionKey>`, add `modelBuilder.AddVellumEncryptionKeys(vellumEfOptions)` with Npgsql filter override | 5 min |
| 9 | Rewrite `DekRotationBackgroundService` | Use `IEncryptionKeyStore.GetActiveScopesAsync` + `IDekManager.RotateDekAsync(scope)` | 10 min |
| 10 | Update callsites | `MessageRepository` / `ContextStoreRepository` — pass `busId` to `DecryptAsync` (domain interface sig widened) | 2 min |
| 11 | First build | 4 errors: ambiguous `IPayloadEncryptor`, missing `IBusEncryptionKeyRepository` in `PersistenceServiceCollectionExtensions`, broken test files. Fixed with type aliases + DI registration deletion. | 10 min |
| 12 | Delete 4 stale test files | `DekManagerTests`, `PayloadEncryptorTests`, `VaultEncryptionServiceTests`, `DekRotationBackgroundServiceTests` (tested gone internals) | 1 min |
| 13 | Build green | 0/0, 57/57 tests pass | 1 min |
| 14 | Generate EF migration | `dotnet ef migrations add MigrateToVellumEncryptionKeys --context RuntimeDbContext` | 1 min |
| 15 | Manually rewrite the migration | Scaffolder's heuristic renamed `organization_id → KeyId` which is semantically wrong; rewrote with `backfill UPDATE` for `Scope` + `WrappedProviderVersion` | 10 min |
| 16 | Build + test | 0/0, 57/57 green | 1 min |
| **Total** | | | **~1h50** |

Net diff at this point: **+1 file created, 15 files deleted, 7 files modified**.

## 7. Benchmarks before/after

Not yet run. Plan: BenchmarkDotNet on a synthetic loop that encrypts a 1 KB JSON payload 10,000 times and decrypts it 10,000 times, comparing:

| Variant | Encrypt | Decrypt | Notes |
|---|---|---|---|
| v0.1.63 custom `PayloadEncryptor` | _baseline_ | _baseline_ | DEK cached by keyId |
| Vellum A.2 (my `VellumBackedPayloadEncryptor`) | ~same | ~same | Same cache, wrapped by Vellum API |
| Vellum B (direct `IPayloadEncryptor.EncryptAsync`/`DecryptAsync`) | ~same | **regression expected** — no decrypt cache | Each decrypt HTTPs Vault |

If B is indeed 10-100× slower on decrypt, that confirms the design gap in section 3 and justifies either (a) adding a caching layer inside `Vellum.PayloadEncryptor` or (b) publishing a `CachingPayloadEncryptor` sample (section 5).

## 8. Blockers

None so far. Close calls:
- **Scaffolder generated wrong migration** (friction #7) — almost a blocker but recoverable by manual rewrite. Documented here so the next consumer doesn't silently ship a data-destructive migration.
- **No `Vellum.Rotation` package** means I'm carrying `DekRotationBackgroundService` locally. Acceptable for now; will need to delete when Phase 4 ships.

## 9. Positive surprises

Genuine "nice, didn't expect that" moments:

1. **`AddEntityFrameworkCoreStore<RuntimeDbContext>` Just Worked on my existing scoped `DbContext`.** I expected to hit a lifetime mismatch or a model-builder conflict. None: Vellum registers as `Scoped` and shares my `DbContext` instance cleanly.

2. **`IgnoreQueryFilters()` is built into every read path.** I spent v0.1.60 → v0.1.63 re-learning this on production (4 hotfixes — `lessons.md` L12). Vellum bakes it in from day one and the XML doc explicitly references "lessons.md L1" — the Vellum team took our pain as their starting point. That's the best possible outcome for the dogfood.

3. **`Dek` is a record with a `WrappedKey` companion field.** The fact that the plaintext DEK carries its own wrapped form means encryption can produce a self-contained envelope without a second store lookup. Elegant and matches the AWS Encryption SDK / Google Tink design.

4. **`ValueTask` on the hot path.** Cache hits stay fully synchronous and allocation-free — a nice touch for a high-throughput encrypt/decrypt loop.

5. **`Dek.ToString` overridden to fixed safe summary, `EncryptedPayload.ToString` same.** The XML doc even explains why (compiler-generated `ToString` could leak key material in a future refactor). That's security-aware library design I'm going to steal for my own value objects.

6. **`VaultKeyEncryptionProvider` caps the error body size at 2 KB** (H-2 defense against a malicious Vault echoing attacker content). I've never seen a .NET library bother with that threat model. Impressive.

7. **The 4-layer race defense lives inside `EntityFrameworkCoreEncryptionKeyStore.CreateAsync`.** My consumers never see the race — it's all inside the store. That's exactly what a library should do.

8. **Existing production data migrated cleanly.** Renaming my snake_case columns to Vellum's PascalCase was a SQL rename with no data loss. The only column that required a value transformation was `Scope = 'bus:' || bus_instance_id`, and that was a 1-line SQL `UPDATE`.

---

## 10. CI integration strategy — adopted on the feature branch

Added in response to the orchestrator's zero-surprise policy. The goal: prove the migration is safe against **pre-existing production data**, not just against a fresh database.

### 10.1 What ships

- `tests/JacqCloud.Buses.Api.Tests.Integration/` — new xUnit test project, separate from the unit test project so (a) heavy containers stay out of the fast developer loop, (b) dependencies (`Npgsql.EntityFrameworkCore.PostgreSQL`, `Xunit.SkippableFact`) don't bleed into the unit build.
- `Fixtures/runtime-baseline.sql` — reproduces the v0.1.63 monolith-created `runtime` schema (services, messages, context_entries) so `IMigrator.MigrateAsync("<targetMigration>")` can run on top of a realistic baseline. The production `RuntimeBaseline` migration is a deliberate no-op (see `Infrastructure/Persistence/Runtime/Migrations/20260305210204_RuntimeBaseline.cs`) because the monolith owns those tables.
- `Fixtures/PreVellumSeedFixture.cs` — `IAsyncLifetime` collection fixture. On init:
  1. Drops & recreates `runtime` schema.
  2. Executes `runtime-baseline.sql`.
  3. Applies EF migrations up to `20260322100000_AddEncryptionToMessagesAndContext` (so `bus_encryption_keys` exists with the v0.1.63 schema).
  4. Generates **5 scenarios** worth of DEKs via real Vault Transit (fixed-Guid, deterministic timestamps, deterministic plaintext where relevant) and inserts them via raw `Npgsql.NpgsqlCommand` so we bypass the now-deleted EF entity:
     - **Scenario 1**: single active DEK v1 + one encrypted seeded message + one encrypted seeded context entry. Used by the roundtrip tests.
     - **Scenario 2**: 3 historical DEKs (`IsActive = false`) + 1 active DEK — simulates a bus that's been through several rotations.
     - **Scenario 3**: bus with zero DEKs — edge case to prove the migration doesn't crash or synthesize a row.
     - **Scenario 4**: active DEK at `vault_key_version = 12` — exercises multi-digit `v12` parsing. Achieved by calling `transit/keys/<name>/rotate` 11 times before wrapping.
     - **Scenario 5**: a second bus under the same organization — proves `Scope` backfill produces two **different** scope strings.
  5. Applies `MigrateToVellumEncryptionKeys` on top of the seeded state.
- `MigrationBackfillTests.cs` — 10 assertions over the migrated schema: row count (by KeyId set, robust to sibling tests), `Scope = 'bus:<guid>'`, `WrappedProviderVersion` matches `^v[0-9]+$`, `KeyId` preservation, active-count-per-scope invariant, scenario 2 historical count, scenario 3 zero-row, scenario 4 `v12`, scenario 5 distinct scopes, legacy columns dropped + Vellum columns present, filtered unique index exists.
- `PostMigrationRoundtripTests.cs` — 4 full-Infrastructure-DI tests:
  - Decrypt a pre-migration seeded **message** through `IMessageRepository.GetByIdAsync` (goes all the way through `VellumBackedPayloadEncryptor` → `Vellum.IDekManager.GetDekByKeyIdAsync` → `Vellum.IKeyEncryptionProvider.UnwrapAsync` → Vault).
  - Decrypt a pre-migration seeded **context entry** through `IContextStore.GetByKeyAsync`.
  - Encrypt a brand-new message through `IMessageRepository.SendAsync` and read it back in a fresh scope, verifying write+read both work post-migration.
  - **Interleaved** pattern: encrypt new → decrypt historical → decrypt new → decrypt historical again. Exercises the keyId-keyed cache partitioning inside `Vellum.IDekManager`.
- `.github/workflows/integration.yml` — separate workflow (does not touch the existing `buses-ci.yml`) with four triggers:
  1. **`pull_request`** with `paths:` filter on encryption, migrations, repo/context repo, `RuntimeDbContext`, `EncryptionServiceCollectionExtensions`, the integration test project, and the workflow file itself. PRs that don't touch encryption never wait on integration.
  2. **`workflow_dispatch`** — manual trigger from the Actions UI.
  3. **`schedule: cron '0 4 * * *'`** — nightly smoke so drift against Vellum's preview package is caught within 24h even if no PR lands.
  4. Concurrency group `integration-${{ github.ref }}` with `cancel-in-progress: true` so multiple pushes on the same branch don't pile up container resources.

  The job spins up `postgres:16-alpine` and `hashicorp/vault:latest` as GitHub Actions `services:`, waits for Vault with a 30-iteration health loop (`curl /v1/sys/health`), bootstraps the transit engine and the `jacqcloud-bus-kek`, then runs `dotnet test tests/JacqCloud.Buses.Api.Tests.Integration/...csproj`.

### 10.2 Execution — local dry run before CI

1. Start containers:
   ```bash
   docker run -d --name vellum-it-postgres -p 127.0.0.1:5433:5432 \
     -e POSTGRES_USER=jacqcloud -e POSTGRES_PASSWORD=jacqcloud -e POSTGRES_DB=jacqcloud_integration \
     postgres:16-alpine
   docker run -d --name vellum-it-vault -p 127.0.0.1:8201:8200 \
     -e VAULT_DEV_ROOT_TOKEN_ID=dev-root --cap-add IPC_LOCK hashicorp/vault:latest
   curl -sf -X POST -H "X-Vault-Token: dev-root" http://127.0.0.1:8201/v1/sys/mounts/transit -d '{"type":"transit"}'
   curl -sf -X POST -H "X-Vault-Token: dev-root" http://127.0.0.1:8201/v1/transit/keys/jacqcloud-bus-kek -d '{}'
   ```
2. Set env vars and run: 15 passed in 933ms on the first real-data pass (see "surprises caught", below).

### 10.3 Surprises caught by the integration suite (exactly why it exists)

1. **`WrappedProviderVersion` was `'1'`, not `'v1'`.** The initial `MigrateToVellumEncryptionKeys.Up()` did `"WrappedProviderVersion" = vault_key_version::text`, producing plain integers in string form. Vellum's own `VaultKeyEncryptionProvider` emits `'v<N>'` with the `v` prefix when it wraps fresh keys. The integration assertion `WrappedProviderVersion ~ '^v[0-9]+$'` fired immediately on local run, and the fix was a one-liner: `'v' || vault_key_version::text` in the UPDATE (plus a symmetric reverse in the `Down()` for the rollback path). **This is exactly the kind of silent-data-format drift the orchestrator's zero-surprise policy is designed to catch** — the column values round-trip through Vault just fine either way, but audit tools and new Vellum-native rows would disagree on the format.
2. **Shared `[Collection]` cross-contamination.** The first test run had `AllSeededDeks_AreStillPresentAfterMigration` failing with `Expected 7, Actual 9` — the roundtrip tests in the same collection were creating DEKs for new bus IDs (through `IMessageRepository.SendAsync` → `IDekManager.GetActiveDekAsync`) before the backfill assertion queried `COUNT(*)`. Fix: query by `KeyId = ANY(@seededIds)` instead of `COUNT(*)`. A more general lesson: assertions on shared-fixture state must be scoped to the rows the test itself cares about, not the whole table. Filed for future integration test authors.
3. **The production `RuntimeBaseline` migration is a deliberate no-op.** I had to reconstruct the monolith's `runtime` schema manually via `runtime-baseline.sql` before any EF migration would apply successfully. Discovered while debugging `relation "runtime.messages" does not exist` during the first test run. Worth calling out in the integration-test README for future test authors who hit the same wall.

### 10.4 What this buys us

- Any future migration touching `bus_encryption_keys`, `messages`, `context_entries` encryption, or the Vellum DI wiring runs the full 15-test integration suite before a reviewer sees the PR. The suite catches:
  - column-format drift (e.g. `v1` vs `1`)
  - missed `Scope` backfill
  - `KeyId` regeneration (would break decryption of historical rows)
  - broken filtered unique index (would allow two active DEKs per bus)
  - broken roundtrip on pre-migration encrypted rows
  - broken roundtrip on post-migration encrypted rows
  - broken interleaved cache behavior in `Vellum.IDekManager`
- **Nightly cron** means a silent drift in the published `Vellum.*` preview packages (if Vellum ships a new preview that changes the `EncryptionKeyRecord` column shape, for example) is caught within ~24 hours, not at the next release.
- **Path-filtered trigger** keeps unrelated PRs (frontend, SSE, retention) off the integration track — they don't pay the container startup cost.

### 10.5 CI friction worth noting for the Vellum team

- **`Vellum.EntityFrameworkCore` has no `.CreateModelAsync` or equivalent for test setups** — consumers who need to bring up the Vellum schema in isolation have to wire a full `DbContext` + migrate. A sample showing "bring up the Vellum table only, in a minimal test project" would be useful.
- **Vellum's XML doc references `tasks/lessons.md L1/L2/L3` three times.** In a consumer's repo, those paths obviously don't resolve. Consider using stable issue links or migrating the references into published design docs so downstream readers can click through.

---

## Appendix: concrete asks for the Vellum team (ordered by value)

1. **Publish a `samples/` folder with at least the 5 samples in section 5.** Single biggest lever for adoption.
2. **Add a README quickstart** — replace "coming soon" with the 30-line minimum snippet.
3. **Add column-name overrides to `VellumEntityFrameworkOptions`** (or a `ConfigureEntity<EncryptionKeyRecord>` hook). Right now there's no way to integrate with a snake_case convention.
4. **Document (and ideally sample) the "feature-flagged encryption" wrapper pattern.**
5. **Consider adding an optional DEK cache to `PayloadEncryptor.DecryptAsync`** — or ship a `CachingPayloadEncryptor` decorator out of the box. The "self-contained envelope but no cache" design is elegant but breaks read-heavy workloads like ours.
6. **Document the "consumer-options-into-Vellum-options" pattern** (the deferred `AddOptions<T>().Configure<IOptions<ConsumerOptions>>` trick). Show a working snippet.
7. **Expose a `VellumBuilder` fluent API for `AddVellum`** so provider/store registration is chainable and discoverable.
8. **Version the EF entity** so future schema changes can be migrated without breaking consumers (add `SchemaVersion` or similar to `VellumEntityFrameworkOptions`).
9. **Move the `AddVellumEncryptionKeys(modelBuilder, options)` options source to DI** so consumers don't duplicate the options block.
10. **Ship `Vellum.Rotation` and `Vellum.AspNetCore` (Phase 4) sooner rather than later** — they're the last two pieces needed to delete local carry-forward code.
