# Migrating from a custom envelope encryption implementation

> **Audience.** A .NET developer with a working but painful custom envelope encryption
> implementation in production — usually one or two classes named `PayloadEncryptor` /
> `DekManager` / `EncryptionService`, a side table for wrapped DEKs, a `DbUpdateException`
> catch block for the creation race, and a nagging feeling that "we'll clean this up one
> day".
>
> **Budget.** Plan for **1–2 weeks** of calendar time including integration tests, staged
> rollout, and a rollback rehearsal. The actual code changes are small (~200 lines added,
> ~150 lines deleted in the reference migration) but the validation work is not.
>
> **Expected outcome.** Zero data loss. Zero downtime. Historical ciphertexts decrypt
> cleanly through the new stack. New encryptions use the new stack from day one. Rollback
> is a single revert of the feature branch and still leaves the data in a decryptable
> state.

This guide is based on **three iterations of real consumer feedback** from an early
adopter who migrated a multi-tenant message-bus backend from a hand-rolled encryption
layer to Vellum `0.1.0-preview.1`, then upgraded through `preview.2` and `preview.3`. The
section 6 recipe below is the step-by-step timeline of that migration, anonymised and
generalised. Every pitfall listed in section 9 is a footgun that bit them for real.

- [When to migrate](#when-to-migrate)
- [What you'll gain](#what-youll-gain)
- [What you'll have to reimplement](#what-youll-have-to-reimplement-or-carry-locally)
- [Step-by-step recipe](#step-by-step-recipe)
- [Schema mapping](#schema-mapping)
- [Migration SQL pattern](#migration-sql-pattern-backfill-via-join)
- [Integration testing the migration](#integration-testing-the-migration)
- [Common pitfalls](#common-pitfalls)
- [Rollback strategy](#rollback-strategy)
- [Closing the loop — a real-world 3-iteration dogfood](#closing-the-loop--a-real-world-3-iteration-dogfood)

## When to migrate

A good candidate for this migration has most of these pain points:

- **Copy-pasted AES-GCM setup** across two or three service classes. If `new AesGcm(...)`
  appears in more than one file, every one of them is a potential bug site.
- **No race-condition test** on the "two pods create the first DEK for a brand-new scope"
  scenario. The library has this test ([see architecture](../architecture.md#race-safe-dek-creation-4-layer-defence));
  your custom code probably does not.
- **A `DbUpdateException` catch block** in the DEK creation path that has grown three or
  four commits over time ("fix the detach", "fix the re-read", "fix the query filter
  bypass") — each one a production incident you fixed retroactively.
- **A DEK cache that hands out the same byte array** to every caller, and a `finally` block
  somewhere that zeroes it. This is a latent memory-corruption bug; the first time one
  caller tries to decrypt while another is still processing a previous call, the second
  caller's DEK bytes are all zero. Lesson L3, production reproducer.
- **Per-tenant keys looked up by `Guid`** without a multi-tenant defence at the cache
  layer. A bug in the slow path that accidentally skips the scope check leaks cross-tenant
  DEKs silently. Lesson L15.
- **Manual snake_case/PascalCase column name juggling** because your DB team insists on
  snake_case and your C# team insists on PascalCase.
- **"One day we'll add OpenTelemetry for encryption"** — probably today's the day you
  could, but the encryption code is scary and nobody wants to touch it.
- **Dogfood anxiety.** You know the code works but there is no structured feedback loop
  to prove it keeps working after every change. An integration test that seeds
  pre-migration rows and asserts round-trip decryption is the single highest-value test
  you can add, and it is infinitely easier to write against a library than against a
  hand-rolled path.

If you check three or more of these boxes, Vellum is probably worth the switch.

## What you'll gain

The migration replaces your hand-rolled code with the library equivalents, and drops the
following classes of bugs permanently:

| Gain | What Vellum gives you | Source |
|---|---|---|
| **`IgnoreQueryFilters()` on every DEK read** | Built into `EntityFrameworkCoreEncryptionKeyStore`. You cannot forget it because there is no escape hatch that omits it. | Lesson L1 — this was a production incident that drove Vellum's design |
| **4-layer race defence on DEK creation** | Double-check, wrap-with-zeroize, filtered unique index, re-read winner via IgnoreQueryFilters. All inside `DekManager.CreateDekAsync` + `EntityFrameworkCoreEncryptionKeyStore.CreateAsync`. | Lesson L2, [architecture](../architecture.md#race-safe-dek-creation-4-layer-defence) |
| **Clone-before-return in every cache path** | Every `GetActiveDekAsync` / `GetDekByKeyIdAsync` / `GetDekByWrappedKeyAsync` path returns a freshly cloned `Dek.Key` byte array. The cached entry is untouched no matter what the caller does with theirs. | Lesson L3 |
| **Memory zeroing in `finally`** | `PayloadEncryptor.EncryptAsync` and `DecryptAsync` zero the plaintext DEK bytes whether AES-GCM succeeds or throws. | `src/Vellum.Core/PayloadEncryptor.cs` |
| **Multi-tenant cache partitioning** | Cache keys are `vellum:dek:active:{scope}` and `vellum:dek:id:{scope}:{keyId}`. A guessed `Guid` cannot retrieve another tenant's cached DEK because the scope is in the key. | Lesson L15 |
| **Scope-safe wrapped-ciphertext decrypt cache** | The decrypt path caches unwrapped DEKs keyed by a SHA-256 hash of the wrapped ciphertext. This is globally unique per tenant by construction — see lesson L24 for the formal argument. Read-heavy workloads pay at most one KEK round-trip per distinct envelope. | Lesson L24, `DekManager.GetDekByWrappedKeyAsync` |
| **Stable EventId logging** | Every `DekManager` log line has a deterministic EventId (`1001` not-found, `1002` cross-scope, `1003` cache invariant violation, …). SIEM rule authoring on these is trivial and does not drift when log messages are reworded. | `src/Vellum.Core/DekManager.cs` LoggerMessage block |
| **`ValidateOnStart()` on every options type** | `VellumOptions`, `VaultOptions`, `StaticOptions`, `VellumEntityFrameworkOptions` all have validators that run at host start. Misconfiguration fails the boot, not the first request. | `*ServiceCollectionExtensions.Add*` |
| **Self-contained envelopes** | `EncryptedPayload` carries its own wrapped DEK, so decryption has zero store round-trips. This is the same design as the AWS Encryption SDK and Google Tink. | `EncryptedPayload.WrappedDek` |

## What you'll have to reimplement or carry locally

Vellum is deliberately narrow. Three consumer concerns are out of scope for the core
packages and you will need to carry them locally during the migration window and possibly
beyond:

| Concern | Status in Vellum | Workaround for now |
|---|---|---|
| **Background DEK rotation worker** | Planned for `Vellum.Rotation` (0.4.0) | Keep your existing `BackgroundService`. Replace the "generate + wrap + persist" body with a single `await dekManager.RotateDekAsync(scope, ct);` call. See the FAQ for a 30-line sketch. |
| **OpenTelemetry metrics / spans** | Planned for `Vellum.AspNetCore` (0.4.0) | Subscribe to the `LoggerMessage`-generated log entries and emit counters / histograms yourself, or wait for `0.4.0`. |
| **ASP.NET Core health checks** | Planned for `Vellum.AspNetCore` (0.4.0) | If you need a "Vault reachable?" health check today, write a trivial `IHealthCheck` that calls `IKeyEncryptionProvider.WrapAsync` with a throwaway buffer. |
| **Feature-flagged encryption wrapper** | Documented pattern, not a built-in toggle | Either call your own `IOptions<FeatureFlags>` at every call site (simplest, most visible), or wrap `IPayloadEncryptor` with Scrutor's `services.Decorate<>`. See [`samples/FeatureFlagged`](../../samples/FeatureFlagged/README.md) for the reference implementation of both variants. |
| **Automatic ciphertext re-encryption on rotation** | Out of scope forever | Vellum never re-encrypts historical payloads during rotation because envelopes are self-contained. If your compliance rules require re-encryption, write a background job that reads historical rows, decrypts, re-encrypts with the current DEK, and writes them back. |

None of these is a blocker for day-1 adoption. The early adopter shipped to production on
`0.1.0-preview.2` with the rotation worker and the feature-flag gate carried locally,
then removed half the local carry in `preview.3` once the attribute landed.

## Step-by-step recipe

Timings are approximate, measured against the reference migration (a mid-size .NET 10
backend with three encrypted tables). Your mileage will vary with the size of your test
suite and the amount of pre-existing encryption code.

| # | Step | Typical time |
|---|---|---|
| 1 | [Branch and install packages](#1-branch-and-install-packages) | 5 min |
| 2 | [Baseline build on the branch with no code changes](#2-baseline-build) | 1 min |
| 3 | [Read the README quickstart and skim the architecture doc](#3-read-the-docs) | 20 min |
| 4 | [Decide on a scope convention](#4-decide-on-a-scope-convention) | 10 min |
| 5 | [Delete your domain encryption interfaces](#5-delete-your-domain-encryption-interfaces) | 5 min |
| 6 | [Rewrite the DI wiring](#6-rewrite-the-di-wiring) | 15 min |
| 7 | [Decorate `DbContext` with `[VellumEntityFrameworkOptions]`](#7-decorate-dbcontext) | 5 min |
| 8 | [Add the `modelBuilder.AddVellumEncryptionKeys(this)` call](#8-add-the-model-builder-extension) | 2 min |
| 9 | [Update callsites to call `IPayloadEncryptor` directly](#9-update-callsites) | 15 min |
| 10 | [Scaffold the EF migration](#10-scaffold-the-ef-migration) | 2 min |
| 11 | [Hand-rewrite the scaffolded `Up()`](#11-hand-rewrite-the-scaffolded-up) | 15 min |
| 12 | [Build + run your existing unit tests](#12-build-and-run-unit-tests) | 5 min |
| 13 | [Write the integration test that seeds pre-migration rows](#13-write-the-integration-test) | 60–90 min |
| 14 | [Run the integration test locally](#14-run-the-integration-test-locally) | 15 min |
| 15 | [Ship to staging behind the feature flag](#15-ship-to-staging) | 30 min |
| 16 | [Canary to production, monitor, full rollout](#16-canary-to-production) | 1–3 days |

**Total**: ~1 working day of coding, plus a week of staged rollout.

### 1. Branch and install packages

```bash
git checkout -b feature/vellum-migration

dotnet add src/YourApp.Infrastructure package Vellum.Abstractions       --prerelease
dotnet add src/YourApp.Infrastructure package Vellum.Core                --prerelease
dotnet add src/YourApp.Infrastructure package Vellum.Vault               --prerelease
dotnet add src/YourApp.Infrastructure package Vellum.EntityFrameworkCore --prerelease

# For tests:
dotnet add tests/YourApp.Tests.Integration package Vellum.InMemory --prerelease
```

Commit the package additions alone before any code changes — this makes the first bisect
cheap if something goes wrong.

### 2. Baseline build

```bash
dotnet build
```

Zero errors, zero warnings. If the mere act of referencing Vellum breaks your build, you
have a transitive version conflict to resolve before doing anything else.

### 3. Read the docs

- [Getting started](../getting-started.md) — work through the Vault section in your head.
- [Architecture](../architecture.md) — especially the 4-layer race defence diagram and the
  multi-tenant isolation table.
- [FAQ](../faq.md) — scan the questions. Any answer that surprises you is worth following
  the link to the full doc.

An early adopter spent 25 minutes reading 1 581 lines of XML docs to reconstruct the API
shape in their first iteration. Three iterations later, the same discovery takes 20
minutes because the quickstart and samples exist. Pay the 20 minutes.

### 4. Decide on a scope convention

This is the most important decision in the whole migration. The `scope` string:

- partitions keys in the store (`WHERE scope = @scope`),
- partitions DEK cache entries (`vellum:dek:active:{scope}`),
- enforces the multi-tenant defence on `GetDekByKeyIdAsync`.

Pick a convention that:

1. **Matches your existing tenant boundary.** If your hand-rolled code already used
   `bus_instance_id` as the partition, use `bus:{bus_instance_id}` in Vellum. If it used
   `tenant_id`, use `tenant:{tenant_id}`.
2. **Is stable across rotations.** A user display name changes; a GUID does not. Use the
   GUID.
3. **Is verbose enough to spot in logs.** `3fbe9c40-...` is less useful than
   `bus:3fbe9c40-...` when you are reading a log line at 3 am.

Write it down. Every call site that encrypts or decrypts will reconstruct the scope from
context, so having "the convention" documented in one place (typically a static helper
class) removes ambiguity.

### 5. Delete your domain encryption interfaces

This is the scary step, but it is the cleanest one. Delete:

- `IEncryptionService` / `IPayloadEncryptor` / whatever your domain interface was.
- `DekManager` / the class that handled "find active DEK or create one".
- `IBusEncryptionKeyRepository` / whatever your DEK store abstraction was.
- The EF entity for your DEK table (`BusEncryptionKey`, `EncryptionKeyEntity`, …).
- The `OnConfiguring` / `OnModelCreating` entity registration for that entity.
- Any records that represented "plaintext DEK + keyId" or "(ciphertext, nonce, wrappedKey)".

Do not delete the table itself — the migration in step 11 renames the columns in place.

If any of these types are referenced from your test suite, delete those tests too. The
integration test in step 13 will replace them with something far more valuable.

An early adopter deleted 11 files in this step in their first iteration and 100+ lines of
adapter code in their second iteration. The second iteration was only possible because
Vellum `preview.2` shipped the decrypt-path cache (#6), which obsoleted their custom
`VellumBackedPayloadEncryptor` adapter — a ~100-line class that existed solely because
`preview.1` did not cache on decrypt. Start on `preview.3`; you will never write that
class.

### 6. Rewrite the DI wiring

Replace your hand-rolled `AddEncryption` / `AddVault` extension with three calls:

```csharp
// In Program.cs or YourApp.Infrastructure/ServiceCollectionExtensions.cs

services.AddDbContext<AppDbContext>(options => options
    .UseNpgsql(builder.Configuration.GetConnectionString("App")));

services.AddVellum(opts => opts.DekCacheTtl = TimeSpan.FromMinutes(30));

services.AddVaultProvider(opts =>
{
    opts.Address = builder.Configuration["Vault:Address"]!;
    opts.Token   = builder.Configuration["Vault:Token"]!;     // loaded from secret store
    opts.KeyName = builder.Configuration["Vault:KeyName"]!;
});

services.AddEntityFrameworkCoreStore<AppDbContext>();
```

If your consumer options come from a `appsettings.json`-bound POCO that you cannot read
at registration time, use the deferred pattern documented in
[consumer options bridging](../consumer-options-bridging.md):

```csharp
services.Configure<YourEncryptionOptions>(builder.Configuration.GetSection("Encryption"));

services
    .AddVellum(_ => { })
    .AddVaultProvider(_ => { })
    .AddEntityFrameworkCoreStore<AppDbContext>(_ => { });

services.AddOptions<VaultOptions>()
    .Configure<IOptions<YourEncryptionOptions>>((vault, consumer) =>
    {
        vault.Address = consumer.Value.VaultAddress;
        vault.Token   = consumer.Value.VaultToken;
        vault.KeyName = consumer.Value.KeyName;
    });
```

**Never call `services.BuildServiceProvider()` inside a registration delegate.** It
creates a disposable root container, leaks singletons, and breaks validation.

### 7. Decorate `DbContext`

Add the `[VellumEntityFrameworkOptions]` attribute on your `DbContext` class. This is the
key step for snake_case-schema consumers and the single most important step for avoiding
the scaffolder footgun in step 11:

```csharp
using Vellum.EntityFrameworkCore;

[VellumEntityFrameworkOptions(
    TableName = "bus_encryption_keys",          // keep your existing table name
    KeyIdColumnName = "key_id",
    ScopeColumnName = "scope",
    WrappedCiphertextColumnName = "wrapped_ciphertext",
    WrappedProviderVersionColumnName = "wrapped_provider_version",
    CreatedAtColumnName = "created_at",
    ExpiresAtColumnName = "expires_at",
    IsActiveColumnName = "is_active",
    UniqueActiveIndexFilter = "\"is_active\" = true")]   // Npgsql syntax
public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    // ...
}
```

Every attribute property you leave unset keeps the Vellum default. If you want to stay
PascalCase, delete the `*ColumnName` properties entirely.

### 8. Add the model builder extension

```csharp
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    ArgumentNullException.ThrowIfNull(modelBuilder);
    base.OnModelCreating(modelBuilder);

    // Reads options in this order: UseVellum → [VellumEntityFrameworkOptions] → DI IOptions → defaults.
    // For the attribute path to be picked up, the context type must carry the attribute (step 7).
    modelBuilder.AddVellumEncryptionKeys(this);

    // Your other entity configurations continue below...
}
```

### 9. Update callsites

This is the mechanical step. Every `await _encryptionService.EncryptAsync(plaintext, tenantId)`
becomes `await _payloadEncryptor.EncryptStringAsync(plaintext, $"bus:{tenantId}")` (or
whatever scope convention you picked in step 4). Every
`await _encryptionService.DecryptAsync(ciphertext, nonce, keyId, tenantId)` becomes
`await _payloadEncryptor.DecryptStringAsync(envelope)` — and `envelope` is constructed from
the row's ciphertext/nonce/wrappedDek columns.

If your existing schema stores only `(ciphertext, nonce, keyId)` per encrypted row and
**not** the wrapped DEK, you have two choices:

1. **Add two nullable columns (recommended).** `wrapped_dek_ciphertext` and
   `wrapped_dek_provider_version`. Back-fill them from your DEK store during the
   migration (step 11's `UPDATE ... FROM JOIN` pattern). This is the early adopter's
   iteration-2 approach, and it is what made the adapter deletion possible. After the
   backfill, the decrypt path is self-contained and does zero store round-trips.
2. **Keep a shim layer temporarily.** Write an `IPayloadEncryptor` decorator that, on
   decrypt, reads the `keyId` from the envelope and calls
   `IDekManager.GetDekByKeyIdAsync(keyId, scope)` to resolve the wrapped DEK from the
   store. This works but re-introduces a store round-trip on every decrypt. Prefer
   option 1.

### 10. Scaffold the EF migration

```bash
dotnet ef migrations add MigrateToVellum \
    --context AppDbContext \
    --output-dir Infrastructure/Migrations
```

The scaffolder will produce a migration. Do not ship it as-is — the next step is
critical.

### 11. Hand-rewrite the scaffolded `Up()`

The scaffolder's rename heuristic will very likely produce a semantically wrong
migration. The early adopter hit exactly this:

- The scaffolder decided their `organization_id` column should be renamed to `KeyId`,
  because both were GUIDs and Vellum defaults to `KeyId` as the PK column. This is a data
  disaster — `organization_id` is a tenant identifier, `KeyId` is the DEK's own identity.
- The scaffolder did not add a `Scope` column because it did not know the column existed;
  the consumer had to `AddColumn` and back-fill by hand.
- The scaffolder did not rewrite the filtered unique index filter from the consumer's
  existing `is_active = true` to Vellum's default `[IsActive] = 1`, because both columns
  existed in the intermediate state.

Replace `Up()` with a hand-written version that:

1. Drops the legacy filtered unique index (you will re-create it at the end pointing at
   the new `scope` column).
2. Drops any columns Vellum does not use (e.g. `organization_id` if your old schema had
   one). Their data lives in `scope` now.
3. Renames the legacy `id` PK to whatever the Vellum `KeyIdColumnName` is (e.g. `key_id`).
4. Adds the `scope` column, back-fills it via `UPDATE` from the tenant column that used
   to live here.
5. Adds the `wrapped_provider_version` column, back-fills it from the legacy KEK version
   column using the **`'v' || N`** format (see pitfall 1 below — this is the one that
   caught fire in the iteration-1 integration test).
6. Drops the legacy tenant column and the legacy KEK version column now that every row
   has the Vellum-native ones.
7. Renames the remaining columns to Vellum's names (or keeps them if you are using the
   column-name overrides from step 7).
8. Recreates the filtered unique index on `scope` with `is_active = true` (or the correct
   syntax for your provider).
9. Re-creates any non-unique index on `scope` for historical lookups.

The full reference migration for a PostgreSQL consumer with an `organization_id` tenant
column lives in
[`samples/MigrationFromCustom/README.md`](../../samples/MigrationFromCustom/README.md). It
is 180 lines and covers every step above.

**Always write a symmetric `Down()`** before shipping the migration. The early adopter
shipped with a `throw new NotImplementedException()` placeholder in their first iteration
and had to fix it under pressure before the production rollout — rolling forward in prod
without a tested `Down()` is how data disasters happen.

### 12. Build and run unit tests

```bash
dotnet build
dotnet test tests/YourApp.Tests.Unit
```

You should be green at this point. Any remaining failures are almost always one of:

- **Test referencing a type you deleted in step 5.** Delete the test too.
- **Type-alias collision** if your domain interface was named `IDekManager` and you
  imported `Vellum.IDekManager` in the same file. The fix is
  `using VellumDekManager = Vellum.IDekManager;`, or (cleaner) rename your file so it only
  imports Vellum's version.
- **`DateTimeOffset` vs `DateTime` mismatch.** `EncryptionKey.CreatedAt` and `ExpiresAt`
  are `DateTimeOffset`, not `DateTime`. If your repository test writes rows by hand with
  `DateTime` values, the type system will catch it. On PostgreSQL the physical column type
  is `timestamptz` in both cases and Npgsql transparently maps both CLR types to it, so
  the migration itself is a no-op on disk.

### 13. Write the integration test

This is the single highest-value test in the whole migration. It does five things:

1. Creates a database, applies the legacy baseline migration, seeds representative rows.
2. Applies `MigrateToVellum` on top.
3. Asserts the schema is in the expected shape post-migration.
4. Round-trips a **pre-migration** encrypted row through the new Vellum stack. If this
   fails, the `KeyId` preservation or the `WrappedCiphertext` rename corrupted the
   envelopes.
5. Round-trips a **brand-new** Vellum-native encrypt through the same `DbContext`. If this
   fails, the post-migration write path is broken.

Seed at least five scenarios so the assertions catch edge cases:

| Scenario | What it proves |
|---|---|
| Single active DEK + one encrypted message | Happy path — the most common real-world shape |
| Three historical DEKs + one active DEK | Rotation history is preserved |
| Zero DEKs for a tenant | The migration does not crash or synthesise a row |
| Active DEK at KEK version 12 | Multi-digit `v12` parsing — catches `v1` vs `v12` string comparison bugs |
| Two tenants under the same "parent" entity | Scope back-fill produces two distinct scope strings |

On top of the seeded rows, assert the following:

- **Row count** is `WHERE KeyId = ANY(@seededIds)`. **Never use `COUNT(*)`** — sibling
  tests in the same shared fixture will create new DEKs during their run and poison the
  assertion. This is pitfall 2 below; the early adopter hit it on their first run.
- **Scope format** matches your convention (`^bus:[0-9a-f-]+$`).
- **`WrappedProviderVersion`** matches `^v[0-9]+$` — the assertion that fired in iteration
  1 and caught the `v1` vs `1` format drift.
- **`KeyId` preservation** — every original identifier is still present.
- **Exactly one active row per scope**.
- **Legacy columns are gone**.
- **Vellum columns are present** (either PascalCase defaults or your snake_case overrides).
- **Filtered unique index exists** with the correct filter syntax.

Then the round-trip tests:

- Decrypt a pre-migration seeded encrypted row via `IPayloadEncryptor.DecryptStringAsync`
  all the way through to the plaintext. If the seed used the legacy schema, you will need
  to reconstruct the `EncryptedPayload` from the row columns; if the seed used the new
  "wrapped-dek-on-row" schema (see step 9 option 1), it is a direct map.
- Encrypt a brand-new plaintext via `IPayloadEncryptor.EncryptStringAsync` and read it
  back in a fresh DI scope. This proves the write path works end-to-end.
- **Interleave the two**: encrypt new → decrypt historical → decrypt new → decrypt
  historical again. This exercises the decrypt-path cache and catches any regression in
  the cache key partitioning.

Run the whole suite against a real PostgreSQL container and a real Vault dev server, not
against mocks. The early adopter wired both as GitHub Actions `services:` and used
`hashicorp/vault:latest` + `postgres:16-alpine`. The total workflow runtime is about 90
seconds on a GitHub-hosted runner.

### 14. Run the integration test locally

```bash
# Postgres + Vault containers
docker run -d --name vellum-it-postgres -p 127.0.0.1:5433:5432 \
    -e POSTGRES_USER=vellum -e POSTGRES_PASSWORD=vellum -e POSTGRES_DB=vellum_it \
    postgres:16-alpine

docker run -d --name vellum-it-vault -p 127.0.0.1:8201:8200 \
    -e VAULT_DEV_ROOT_TOKEN_ID=dev-root --cap-add IPC_LOCK \
    hashicorp/vault:latest

curl -sf -X POST -H "X-Vault-Token: dev-root" \
    http://127.0.0.1:8201/v1/sys/mounts/transit -d '{"type":"transit"}'
curl -sf -X POST -H "X-Vault-Token: dev-root" \
    http://127.0.0.1:8201/v1/transit/keys/integration-kek -d '{}'

dotnet test tests/YourApp.Tests.Integration
```

If the suite is green, commit. If a single assertion fires, treat it as a real bug —
this is exactly what the suite is for. Pitfall 1 below was caught this way in the
reference migration, and the fix was one `UPDATE` statement.

### 15. Ship to staging

Deploy the branch to staging with the feature flag **off**. Decrypt throughput should be
unchanged (the new code path is not hit). Then flip the flag on for staging and run a
24-hour soak:

- Monitor for `OptionsValidationException` at startup (would indicate misconfiguration
  you did not catch).
- Monitor for `CryptographicException` in your logs (would indicate a corrupted envelope
  or a bad auth tag).
- Monitor for `InvalidOperationException` with the string "does not belong to scope"
  (would indicate a bug in your scope convention — a call site is reconstructing the
  scope differently for encrypt vs decrypt).
- Monitor for `KEK provider is temporarily unavailable` — if this fires, your retry /
  circuit-breaker policy on the Vault `HttpClient` is not wired correctly.

The EventIds in `DekManager` (`1001`, `1002`, `1003`) are designed for exactly this kind
of alerting — add a SIEM rule per EventId.

### 16. Canary to production

Roll out the feature flag to production in three waves:

1. **1% of traffic for 24 hours.** Watch the same metrics as staging. If anything goes
   wrong, flip the flag off — the old code is still running and the data written during
   the canary is readable because the envelopes are self-contained.
2. **10% of traffic for 48 hours.** Same monitoring. This is the point at which you are
   most likely to catch a performance regression (the built-in decrypt cache should make
   read-heavy workloads a wash; if it does not, something is wrong).
3. **100%.** Let it soak for a week, then delete the feature flag and the old code path
   in a follow-up PR.

Once the follow-up PR lands, the migration is done. The only remaining local carry is
your rotation `BackgroundService` and whatever feature-flag wiring you kept for the
encryption toggle. Both are ~50-line classes and will go away when `Vellum.Rotation` and
`Vellum.AspNetCore` ship in 0.4.0.

## Schema mapping

Mapping from a typical custom `bus_encryption_keys` table to Vellum's shape. Use the
`[VellumEntityFrameworkOptions]` attribute (step 7) to preserve snake_case naming — every
column that Vellum exposes can be renamed, and every property you leave unset keeps the
Vellum default.

| Legacy column | Type | Vellum column | Type | Notes |
|---|---|---|---|---|
| `id` | `UUID` | `key_id` | `UUID` | Rename only — the UUID values are preserved 1:1. |
| `bus_instance_id` | `UUID` | — | — | Dropped; its content lives in `scope` after backfill. |
| `organization_id` | `UUID` | — | — | Dropped; Vellum does not have a two-level tenant concept. Fold into `scope` if needed (`"org:{org}:bus:{bus}"`). |
| `encrypted_dek` | `VARCHAR(2048)` | `wrapped_ciphertext` | `TEXT` (unbounded) | Rename only — the ciphertext string is round-tripped verbatim to the KEK provider. |
| `vault_key_version` | `INT` | `wrapped_provider_version` | `VARCHAR(512)` | Transform: **`'v' || vault_key_version::text`** — the `v` prefix is mandatory because `VaultKeyEncryptionProvider.WrapAsync` emits `'v<N>'` on fresh wraps. See pitfall 1 below. |
| `created_at` | `TIMESTAMPTZ` | `created_at` | `TIMESTAMPTZ` | No data change. |
| `expires_at` | `TIMESTAMPTZ NULL` | `expires_at` | `TIMESTAMPTZ NULL` | No data change. |
| `is_active` | `BOOLEAN` | `is_active` | `BOOLEAN` | No data change; referenced by the filtered unique index. |
| — | — | `scope` | `VARCHAR(256)` | Added; back-filled via `UPDATE SET scope = 'bus:' \|\| bus_instance_id::text;`. Maximum length is tuneable via `VellumEntityFrameworkOptions.ScopeMaxLength` (default 256). |

## Migration SQL pattern (backfill via JOIN)

If your encrypted business rows (messages, context entries, audit events, …) carry only
a `(ciphertext, nonce, key_id)` triple and you want to move to the self-contained envelope
shape, add two nullable columns on each encrypted table and back-fill from the DEK store
via a join:

```sql
-- 1. Add nullable columns so the migration is online-safe.
ALTER TABLE runtime.messages
    ADD COLUMN wrapped_dek_ciphertext TEXT NULL,
    ADD COLUMN wrapped_dek_provider_version VARCHAR(512) NULL;

-- 2. Back-fill from the DEK store in a single statement. This is the "UPDATE ... FROM
--    JOIN" pattern Postgres supports natively; on SQL Server you would use the 
--    "UPDATE m SET ... FROM messages m INNER JOIN ..." form.
UPDATE runtime.messages m
   SET wrapped_dek_ciphertext      = k.wrapped_ciphertext,
       wrapped_dek_provider_version = k.wrapped_provider_version
  FROM runtime.bus_encryption_keys k
 WHERE m.encryption_key_id = k.key_id
   AND m.wrapped_dek_ciphertext IS NULL;

-- 3. Repeat for every other encrypted table (context_entries, audit_events, ...).

-- 4. Verify no NULLs remain (gate step before making the columns NOT NULL).
SELECT COUNT(*)
  FROM runtime.messages
 WHERE encryption_key_id IS NOT NULL
   AND wrapped_dek_ciphertext IS NULL;
-- Expected: 0
```

This pattern is **additive and non-destructive**. If it is interrupted halfway through
or runs into a lock timeout, re-running it is a safe no-op (the `IS NULL` guard on the
`UPDATE` skips rows that have already been back-filled). Ship this in its own migration,
gate the `NOT NULL` constraint change behind a follow-up migration that runs after the
verification query above returns 0, and you have a completely online column addition.

## Integration testing the migration

The test suite you write in step 13 is the single most valuable artefact in this
migration. In the reference case, it caught one silent data-format drift bug (`v1` vs
`1`) that would have shipped to production otherwise. Every subsequent encryption-related
PR on the same repository now runs the suite automatically, and the zero-surprise posture
has held across three iterations.

Key properties of a good migration test suite:

- **Seed pre-migration rows with deterministic identifiers.** Every assertion later is
  `WHERE KeyId = ANY(@seededIds)`. This keeps the test robust against sibling fixtures.
- **Apply the migration in-test, not in a separate step.** The test runs
  `IMigrator.MigrateAsync` (or the equivalent for your DI stack) as the first act after
  seeding. Any failure to apply fails the test, not the test setup.
- **Use real containers**, not `InMemory` or `Sqlite`. Filtered unique indexes behave
  differently on different providers, and the PostgreSQL `UPDATE ... FROM JOIN` syntax
  does not work on SQL Server. Test against what you deploy.
- **One workflow, path-filtered.** Trigger the integration workflow on PRs that touch
  encryption / migrations / repo / context repo / the DbContext / the EncryptionServiceCollectionExtensions /
  the integration test project / the workflow file itself. Unrelated PRs never pay the
  container startup cost.
- **Nightly cron on top.** A scheduled nightly run on `main` catches drift against
  upstream Vellum preview packages within 24 hours even when no PR lands.
- **Concurrency group.** Set `concurrency.group: integration-${{ github.ref }}` with
  `cancel-in-progress: true` so multiple pushes on the same branch do not pile up
  container resources.

The reference workflow is about 120 lines of YAML and ~400 lines of C# — a reasonable
weekend project, and the return on investment is "catch every silent encryption bug
before it ships" for the rest of the project's life.

## Common pitfalls

### 1. `WrappedProviderVersion = '1'` vs `'v1'`

`VaultKeyEncryptionProvider.WrapAsync` emits ciphertexts shaped `vault:v1:{base64}`,
`vault:v2:{base64}`, etc., and stores `"v1"` / `"v2"` verbatim in `WrappedKey.ProviderVersion`.
A back-fill that does `WrappedProviderVersion = vault_key_version::text` (dropping the `v`
prefix) round-trips through Vault fine — Vault only cares about the ciphertext itself,
not the version string — but audit tools and new Vellum-native rows will format-disagree
silently.

The integration assertion is:

```csharp
string actualVersion = /* query from row */;
actualVersion.Should().MatchRegex("^v[0-9]+$");
```

The fix is a one-line change in the migration:

```sql
UPDATE runtime.bus_encryption_keys
   SET wrapped_provider_version = 'v' || vault_key_version::text;
```

This is the bug that caught fire in iteration 1 of the reference migration and is exactly
what the integration suite exists to catch.

### 2. `COUNT(*)` assertions on a shared test fixture

```csharp
// ❌ Flaky — sibling tests create DEKs during their run
int count = await db.Database.ExecuteSqlRawAsync("SELECT COUNT(*) FROM bus_encryption_keys");

// ✅ Robust — scoped to the rows this test seeded
int count = await db.Database.SqlQueryRaw<int>(
    "SELECT COUNT(*) FROM bus_encryption_keys WHERE key_id = ANY({0})",
    seededIds).FirstAsync();
```

The general lesson: **every assertion on a shared-fixture state must be scoped to the
rows the test itself cares about**, not the whole table. Collection-scoped fixtures can
be shared across test classes, and the shared state evolves as sibling tests run.

### 3. `EncryptionKey.KeyId` vs `EncryptedPayload.KeyId`

These are the same UUID, but they live in different records and serve subtly different
purposes:

- **`EncryptionKey.KeyId`** is the primary key of the DEK store. Used for rotation
  tracking and historical lookups via `IDekManager.GetDekByKeyIdAsync`.
- **`EncryptedPayload.KeyId`** is the audit identifier on a single envelope. It is
  **audit-only** — decryption does not need it because the envelope carries its own
  `WrappedDek`. The field exists so you can answer "which DEK was used to encrypt this
  row?" in a query, and so rotation reports can show "these envelopes were written under
  the previous DEK".

If your hand-rolled code used the `keyId` as the primary decrypt lookup key (common), the
cleanest migration is to add `WrappedCiphertext` and `WrappedProviderVersion` columns on
every encrypted row so the decrypt path becomes envelope-self-contained (see
[Migration SQL pattern](#migration-sql-pattern-backfill-via-join)). The `keyId` column on
the encrypted row is then purely audit data.

### 4. Scope format conventions drift between encrypt and decrypt

If `MessageRepository.SendAsync` reconstructs the scope as `$"bus:{busId}"` but
`MessageRepository.GetByIdAsync` reconstructs it as `$"bus:{busId.ToString().ToUpper()}"`,
the encrypt and decrypt sides disagree and every decrypt fails with `InvalidOperationException:
Encryption key {keyId} not found for scope '...'`.

The fix is to **centralise the scope builder**:

```csharp
public static class EncryptionScope
{
    public static string ForBus(Guid busId) =>
        string.Create(CultureInfo.InvariantCulture, $"bus:{busId:D}");
}
```

Every call site uses `EncryptionScope.ForBus(busId)`. The format is now defined in
exactly one place and cannot drift.

### 5. `InMemoryEncryptionKeyStore` thread-safety surprises

`Vellum.InMemory` is safe to use from multiple threads, but its internal serialization
uses a single global lock (intentional — see `InMemoryEncryptionKeyStore.cs` remarks).
If your integration test exercises truly massive concurrency on the in-memory store,
you may see contention. For multi-pod race condition testing you want the EF Core store
with a real filtered unique index — that is the only store that reproduces the full
4-layer race defence.

### 6. `DateTime` vs `DateTimeOffset` mismatch

`EncryptionKey.CreatedAt` and `ExpiresAt` are `DateTimeOffset`. Your legacy entity
probably used `DateTime`. On PostgreSQL, Npgsql transparently maps both CLR types to
`timestamp with time zone`, so the physical column layout is identical and no data
migration is needed on the timestamps. On SQL Server, the legacy `datetime2` maps to
`DateTime` and will need a CLR type change in the migration — the `datetime2` column
itself stays untouched.

### 7. The `VellumBackedPayloadEncryptor` adapter pattern (from iteration 1)

In iteration 1 of the reference migration, the early adopter wrote a custom
`VellumBackedPayloadEncryptor` class that wrapped `Vellum.IDekManager.GetDekByKeyIdAsync`
and ran AES-GCM in-line, specifically because `Vellum.Core.PayloadEncryptor.DecryptAsync`
had no decrypt-path cache at the time. That pattern became obsolete in `preview.2` when
Vellum added the built-in decrypt cache (issue #6), and the adapter was deleted in
iteration 2.

**Do not write a `VellumBackedPayloadEncryptor` today.** Start on `preview.3`, use
`IPayloadEncryptor` directly, and skip the adapter entirely. The only situation that
still benefits from a decorator over `IPayloadEncryptor` is a feature-flag gate — see
[`samples/FeatureFlagged`](../../samples/FeatureFlagged/README.md) for the reference
pattern.

### 8. The scaffolder produces an empty or spurious migration

If you run `dotnet ef migrations add MyFirstVellumMigration` and the scaffolder produces
an empty `Up()` or a migration that wants to rename a table that does not exist, you are
hitting the design-time options resolution gap. The fix is the
`[VellumEntityFrameworkOptions]` attribute from step 7 — see
[FAQ — why do I need the attribute](../faq.md#why-do-i-need-the-vellumentityframeworkoptions-attribute).

This is a real issue that an early adopter hit in iteration 2 of their dogfood, and it is
the reason `preview.3` exists at all.

## Rollback strategy

The single cleanest rollback strategy is the one the reference migration used in iteration
2: **keep the old code paths in the repository during the staged rollout**, behind a
feature flag, and flip the flag off if something goes wrong. Concretely:

1. Keep your legacy `IEncryptionService` interface and its implementation alive on the
   branch. Rename to `IEncryptionServiceLegacy` to avoid the name clash.
2. Your new `IPayloadEncryptor` wiring reads a feature flag (`Encryption.Backend = "vellum" | "legacy"`).
3. At the call sites, resolve one or the other based on the flag.
4. Ship. Monitor. If anything breaks, flip the flag to `"legacy"` — the old code path
   resumes immediately without a redeploy, and any data written under Vellum during the
   window is still readable because envelopes are self-contained.
5. After the soak, delete the legacy code in a follow-up PR.

**Schema-level rollback is harder** and usually not worth attempting. The migration
recipe in step 11 rewrites columns in-place, so a rollback would require a reverse
migration. The reverse migration is straightforward to write (rename columns back,
drop the `scope` column, drop the `wrapped_provider_version` column, restore the old
`vault_key_version` column from `substring(wrapped_provider_version FROM 2)::int`) and
the early adopter shipped one in their production PR, but they never needed to run it.

The feature-flag approach + an untested reverse migration is a reasonable compromise for
most teams. The zero-downtime alternative (run both encryption stacks in parallel and
dual-write to both DEK tables during the migration window) is doable but doubles the
operational complexity and is rarely worth the effort unless the rollback surface is
compliance-critical.

## Closing the loop — a real-world 3-iteration dogfood

This guide is based on a real migration that happened over three iterations of feedback,
each one closing a loop with the Vellum team. The anonymised timeline:

### Iteration 1 — `preview.1`

- Migrated a multi-tenant message bus backend from a hand-rolled encryption layer to
  Vellum `0.1.0-preview.1`. Total time: ~1h50 for the code changes, plus a weekend for
  the integration test suite.
- Filed **9 frictions** and 10 issues against Vellum, plus a wish-list of 5 samples.
- The biggest friction: **no DEK cache on the decrypt path**. Every decrypt round-tripped
  to Vault. The adopter worked around it with a custom adapter class.
- Second-biggest friction: **no column-name overrides** on the EF store. The adopter's
  schema was snake_case; Vellum's defaults were PascalCase. They accepted the mismatch
  for iteration 1.
- Third-biggest friction: **`AddVellumEncryptionKeys` required the options literal twice**.
  Once in the DI extension, once in `OnModelCreating`. The adopter wrote a "keep in sync"
  comment and moved on.
- Integration suite: **15/15 green on first run** — caught one silent format drift bug
  (`v1` vs `1`) before it could reach production.

### Iteration 2 — `preview.2`

- Vellum shipped `0.1.0-preview.2` two weeks later, closing 7 of the 9 frictions:
  - The README quickstart landed.
  - `modelBuilder.AddVellumEncryptionKeys(this)` became the canonical path (issue #9).
  - The decrypt-path cache landed (issue #6) — the adopter empirically verified it with
    a test that counted KEK unwraps on 10 consecutive decrypts of the same envelope.
  - Column-name overrides landed (issue #8).
  - The `samples/` folder landed with 5 canonical samples.
  - The feature-flag wrapper pattern was documented.
  - The consumer-options bridging pattern was documented.
- Adopter upgrade time: **~2 hours**. Deleted 105 lines of the custom adapter class
  (the decrypt cache made it obsolete), 10 lines of domain interfaces, and 6 lines of
  `OnModelCreating` boilerplate. **Net 130 lines removed.**
- New friction discovered: **the EF scaffolder could not see `UseVellum`-attached
  options at design time**. The adopter's `IDesignTimeDbContextFactory` did not call
  `UseVellum`, so the scaffolder silently fell back to defaults and produced a bogus
  migration when the adopter tried to adopt the new snake_case overrides.
- Snake_case adoption: **deferred** because of the design-time gap.
- Integration suite: **16/16 green** (+1 decrypt-cache-hit test).

### Iteration 3 — `preview.3`

- Vellum shipped `0.1.0-preview.3` a day later in response to iteration 2's friction 4.1,
  adding the `[VellumEntityFrameworkOptions]` attribute (issue #17). The attribute is
  reflection-readable at both runtime and design time, so the scaffolder sees it
  regardless of whether `UseVellum` was chained.
- Adopter upgrade time: **~90 minutes** for the migration plus the snake_case rename
  that had been deferred in iteration 2. One hand-edit required on the scaffolded
  migration (spurious `RenameTable` from a stale model snapshot committed in iteration
  2 — not a `preview.3` bug).
- Integration suite: **17/17 green** (+1 snake_case column assertion verifying the
  exact set of post-migration columns against `information_schema.columns`).
- Snake_case adoption: **shipped to production**. Zero adapter code in Infrastructure,
  zero duplicated options blocks, zero design-time vs runtime divergence.

### Lessons for your migration

- **Start on `preview.3`** (or whatever the latest version is when you read this). The
  intermediate frictions have already been fixed; you get the final canonical shape on
  day one.
- **Plan for iteration.** Your first migration will surface at least one friction that
  was not in this guide. File an issue upstream — the Vellum team responds to consumer
  feedback by shipping releases, not by arguing.
- **The integration suite is not optional.** It caught a silent data-format drift in
  iteration 1, caught the design-time options-visibility gap in iteration 2, and held
  the line across all three iterations. Budget the time to write it.
- **Zero data loss, zero downtime, three iterations of feedback.** This is what a
  well-scoped, empirically-validated migration looks like. The goal is not to be fast;
  the goal is to be boring.

Good luck.
