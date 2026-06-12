# FAQ

Short answers to the questions Vellum actually gets asked. Cross-referenced to the relevant
design docs for the long version.

- [Is Vellum production-ready?](#is-vellum-production-ready)
- [How do I rotate DEKs without downtime?](#how-do-i-rotate-deks-without-downtime)
- [How does Vellum handle multi-tenancy?](#how-does-vellum-handle-multi-tenancy)
- [What happens if a KEK provider is temporarily unavailable?](#what-happens-if-a-kek-provider-is-temporarily-unavailable)
- [Can I use Vellum without EF Core?](#can-i-use-vellum-without-ef-core)
- [How does Vellum compare to `Microsoft.AspNetCore.DataProtection`?](#how-does-vellum-compare-to-microsoftaspnetcoredataprotection)
- [Why does `Vellum.Static` exist and when should I use it?](#why-does-vellumstatic-exist-and-when-should-i-use-it)
- [How do I migrate from a custom envelope encryption implementation?](#how-do-i-migrate-from-a-custom-envelope-encryption-implementation)
- [Does Vellum support key escrow or split knowledge?](#does-vellum-support-key-escrow-or-split-knowledge)
- [What's the performance impact of the DEK cache?](#whats-the-performance-impact-of-the-dek-cache)
- [What TFMs does Vellum target?](#what-tfms-does-vellum-target)
- [Why do I need the `[VellumEntityFrameworkOptions]` attribute?](#why-do-i-need-the-vellumentityframeworkoptions-attribute)
- [What's the plan for Azure Key Vault / AWS KMS / GCP KMS support?](#whats-the-plan-for-azure-key-vault--aws-kms--gcp-kms-support)
- [How do I report a security vulnerability?](#how-do-i-report-a-security-vulnerability)
- [Does Vellum ship any telemetry or metrics?](#does-vellum-ship-any-telemetry-or-metrics)

## Is Vellum production-ready?

**Yes, for non-critical production workloads.** Vellum is in use by at least one
real consumer in production (an early adopter's multi-tenant message bus backend, after
three iterations of dogfood feedback that drove most of the pre-1.0 changes). The shipped
packages — `Vellum.Abstractions`, `Vellum.Core`, `Vellum.Vault`, `Vellum.Static`,
`Vellum.InMemory`, `Vellum.EntityFrameworkCore`, and `Vellum.Rotation` — are all fully
tested, all zero-warning builds, and all subject to the same `TreatWarningsAsErrors` +
`AllEnabledByDefault` analyzer posture as the rest of the library.

What is **not** yet production-ready:

- **The public API is not frozen.** It is stable (three iterations of consumer
  feedback drove most of the API shape), but semver guarantees only kick in at
  `1.0.0`. Expect additive changes between now and then; breaking changes, if any, will
  land as clear `CHANGELOG.md` entries with migration notes.
- **Cloud KEK providers are not shipped yet.** `Vellum.AzureKeyVault`, `Vellum.AwsKms`, and
  `Vellum.GcpKms` are planned for `0.3.0`. If you need one of these today, you must
  implement `IKeyEncryptionProvider` yourself against the cloud SDK — the interface is
  three methods and the Vault provider is the reference implementation.
- **Metrics, health checks, and OpenTelemetry are not shipped yet.** They are planned for
  `Vellum.AspNetCore`; until then, derive dashboards from the structured logs (see
  [Does Vellum ship any telemetry or metrics?](#does-vellum-ship-any-telemetry-or-metrics)).

Verdict: if you are running on .NET 8, 9, or 10 and using HashiCorp Vault Transit, Vellum
is usable today — including scheduled background rotation via the opt-in `Vellum.Rotation`
package. Otherwise, wait for `0.3.0`.

## How do I rotate DEKs without downtime?

`IDekManager.RotateDekAsync(scope)` is atomic and fail-safe: it generates and wraps the
new DEK *before* touching anything, then swaps the active key via
`IEncryptionKeyStore.RotateAsync` (deactivate-old + insert-new in one transaction), then
replaces the cache entry. If the KEK provider or the store fails at any point, the old key
stays active *and* cached — the scope is never observed without an active DEK. Historical
envelopes remain fully decryptable because `EncryptedPayload` carries its own
`WrappedDek` — a rotation is a write-path operation only, it never re-encrypts existing
data.

There is zero downtime because:

1. Payloads encrypted **before** the rotation still decrypt via the embedded `WrappedDek`
   on the envelope. They never consult the store during decryption.
2. Payloads encrypted **during** the rotation call either win or lose the race on the
   filtered unique index — the loser re-reads the winner's wrapped key and encrypts
   against it, exactly like the 4-layer defence on first-time creation (see
   [architecture — race-safe DEK creation](architecture.md#race-safe-dek-creation-4-layer-defence)).
   Within a single process, a per-scope async lock serialises create/rotate/slow-read so
   the race never even reaches the store.

For scheduled rotation, add the opt-in **`Vellum.Rotation`** package — a hosted worker
that ticks every `RotationInterval`, rotates only scopes whose active key is older than
`MaxDekAge`, and retries failed scopes with exponential backoff and jitter inside the tick:

```csharp
services.AddVellumRotation(o =>
{
    o.RotationInterval   = TimeSpan.FromHours(24); // how often the worker ticks
    o.MaxDekAge          = TimeSpan.FromHours(24); // rotate only keys at least this old
    o.MaxRetriesPerScope = 3;                      // per-scope retry with backoff in the tick
});
```

One scope failing never blocks the others, and `Vellum.Core` itself never starts a
background service — rotation stays opt-in. See the
[key rotation runbook](kek-rotation.md) for the full operational picture, including KEK
rotation on the Vault side.

## How does Vellum handle multi-tenancy?

Through an **opaque `scope` string** the consumer picks. Vellum never interprets the
content; it just uses it as a partition key on every read, write, and cache entry — and,
by default, bakes it into the ciphertext itself: format version 2 envelopes carry the
scope as AES-GCM associated data, so an envelope copied from one tenant's records into
another's fails the authentication tag check instead of decrypting. See
[architecture — multi-tenant isolation](architecture.md#multi-tenant-isolation) for the
full layer table.

In practice, pick a scope convention that matches your tenant boundary:

| Boundary | Example |
|---|---|
| One tenant per customer | `tenant:{customer-guid}` |
| One message bus per workspace | `bus:{workspace-id}` |
| Global (single-tenant app) | `global` |

The scope must be **stable** across encrypt and decrypt for the same data — avoid anything
that can change (user display names, region codes, etc.).

## What happens if a KEK provider is temporarily unavailable?

Vellum **fails closed**. If `IKeyEncryptionProvider.WrapAsync` or `UnwrapAsync` ultimately
fails (HTTP timeout, 5xx, token expired, KEK revoked, …), the exception propagates to the
caller. Vellum never returns the plaintext and never caches "KEK unavailable" as a
successful result.

Three practical implications:

1. **Transient-failure retries are built in (Vault provider, 0.2.0+).** Every Vault
   request goes through the standard HTTP resilience handler — retries with exponential
   backoff on transient failures (5xx, 408, 429, timeouts, connection errors), circuit
   breaker, and per-attempt/total timeouts derived from `VaultOptions.HttpTimeout`. It is
   on by default; set `VaultOptions.EnableResilience = false` inside the `AddVaultProvider`
   delegate to opt out and restore single-attempt behaviour. Only failures that outlast
   the retries propagate to your code.
2. **Expired tokens self-heal with AppRole.** With
   `VaultOptions.AuthMethod = VaultAuthMethod.AppRole`, tokens are re-acquired
   automatically before they expire, and a `403` triggers token invalidation plus a single
   retry with a fresh token. A static token, by contrast, cannot be re-minted — a `403` on
   a static token propagates immediately.
3. **The DEK cache dampens transient outages.** Any DEK that was unwrapped in the last
   `VellumOptions.DekCacheTtl` (default 30 minutes) lives in-process and does not need
   the KEK provider to decrypt. A short Vault outage during peak traffic is mostly
   absorbed by the cache; a long outage blocks new encryptions once the cache expires.

## Can I use Vellum without EF Core?

Yes. `IEncryptionKeyStore` is a plain interface with 8 methods. If you do not want EF
Core, you can:

1. Use the shipped **`Vellum.InMemory`** store for tests and samples.
2. Implement `IEncryptionKeyStore` yourself against any backend — Dapper, Marten,
   MongoDB, DynamoDB, Cosmos DB, Redis, a flat file. The interface is designed to be a
   few hundred lines against any reasonable backend; the contract is fully documented in
   the XML remarks on each method.
3. Register your implementation via `services.TryAddScoped<IEncryptionKeyStore, MyStore>()`
   **before** calling `AddVellum()` — Vellum uses `TryAdd*` throughout so consumer
   registrations always win.

If you write a production-quality non-EF store, please
[open an issue](https://github.com/OkaySire/vellum/issues/new) — we are collecting
candidates for an official `Vellum.Dapper` / `Vellum.Marten` / `Vellum.Redis` package set
once the shape stabilises.

## How does Vellum compare to `Microsoft.AspNetCore.DataProtection`?

They solve different problems. The short version:

- **`DataProtection`** is a small, convenient, mostly invisible library for protecting
  short-lived tokens (antiforgery cookies, TempData, password-reset links, OAuth state).
  It does not implement envelope encryption and has no concept of a KEK-backed per-tenant
  DEK. You point it at a "key ring" that it fully manages, and you never see the
  underlying keys.
- **Vellum** is a library for persisting **long-lived encrypted application data**
  (message bodies, PII fields, audit records) backed by a KEK provider like Vault or KMS.
  You control the DEK lifecycle, the rotation cadence, the multi-tenant boundary, the
  storage schema, and the envelope format.

If you only need to protect a signed cookie or a password reset token, use
`DataProtection`. If you need to encrypt payloads that will live in a database for months
or years with a rotation story that satisfies compliance auditors, use Vellum (or a cloud
SDK, depending on whether you are single-cloud or not).

See [comparison](comparison.md) for a full matrix with Vellum, `DataProtection`, AWS
Encryption SDK, Google Tink, and the "hand-rolled envelope encryption" pattern that most
teams reach for by default.

## Why does `Vellum.Static` exist and when should I use it?

`Vellum.Static` is an `IKeyEncryptionProvider` that holds the KEK as a base64-encoded
string in process memory, bootstrapped from `StaticOptions.Base64Key`. It exists for three
reasons:

1. **Zero-dependency samples.** The `Console.Static` sample has no external containers,
   no Vault, no database — you can `dotnet run` it fresh out of `git clone` and see
   encryption work.
2. **Unit tests.** A test that wants to exercise the full encrypt/decrypt path without
   mocking the KEK can use `Vellum.Static` + `Vellum.InMemory` to get a realistic AES-GCM
   round-trip in-process.
3. **Local development** against code that will run against Vault or KMS in production —
   a developer who is offline or on a laptop without docker can still run the app with a
   sentinel KEK.

**Never use `Vellum.Static` in production.** The provider logs a loud warning on the first
wrap or unwrap call specifically so that a misconfiguration that reaches production is
impossible to miss. The warning event id is `1` in `StaticKeyEncryptionProvider` — add an
alert rule on it in your SIEM and you will catch the mistake within seconds.

The provider's own XML docs spell this out in every file, and the doc comment on the
registration extension repeats it in uppercase. This is deliberate — lesson L7.

## How do I migrate from a custom envelope encryption implementation?

There is a dedicated guide for this — see
[Migrating from a custom implementation](migrations/from-custom.md). It is based on three
iterations of real consumer feedback and includes the exact SQL `UPDATE ... FROM JOIN`
pattern used to back-fill the `Scope` column without data loss, the integration-test seed
fixture that catches silent data-format drift, and the "common pitfalls" section that
aggregates every gotcha from the dogfood reports.

The short version of the migration:

1. Install the packages, keep your old code behind a feature flag.
2. Rewrite the DI wiring to call `AddVellum() + AddVaultProvider() + AddEntityFrameworkCoreStore<T>()`.
3. Decorate your `DbContext` with `[VellumEntityFrameworkOptions]` and call
   `modelBuilder.AddVellumEncryptionKeys(this)` in `OnModelCreating`.
4. Write an EF migration that renames columns, back-fills `Scope` from your existing
   tenant column, and populates `WrappedProviderVersion` from your legacy KEK version.
5. Write an integration test that seeds pre-migration rows, applies the migration, and
   asserts that both historical and new-format envelopes decrypt correctly.
6. Ship in stages: flag-off in dev, flag-on in staging, canary in prod, full prod.

## Does Vellum support key escrow or split knowledge?

**No, and it is not on the roadmap.** Key escrow (storing a copy of every DEK with a
trusted escrow agent so it can be recovered if the KEK is lost) and split knowledge
(breaking a KEK into multiple shares so no single operator can unwrap it) are both
properties of the KEK, not of Vellum's envelope layer.

If you need either property, configure them in your KEK provider:

- **HashiCorp Vault Transit** supports Shamir's Secret Sharing for initial unseal. See
  [Vault unseal and recover](https://developer.hashicorp.com/vault/docs/concepts/seal).
- **AWS KMS** supports multi-Region keys and automatic rotation; split knowledge lives at
  the IAM policy layer.
- **Azure Key Vault** supports BYOK (bring-your-own-key) and role-based access separation.
- **GCP KMS** supports EKM (external key manager) and HSM-backed keys.

Vellum delegates every KEK-level concern to the provider, so anything the provider
supports is transparently available to Vellum consumers.

## What's the performance impact of the DEK cache?

The DEK cache is the difference between "one KEK round-trip per decrypt" and "one KEK
round-trip per distinct DEK". For read-heavy workloads it is the single largest performance
factor in the library.

Since `0.2.0` the cache is a **Vellum-private `VellumDekCache`**, not the application's
shared `IMemoryCache`: other in-process code cannot read the plaintext DEK entries,
consumer `SizeLimit` budgeting or compaction cannot evict them, and key bytes are zeroed
when an entry is evicted, expired, or replaced. `AddVellum()` consequently no longer calls
`AddMemoryCache()` — if your own code relied on that registration, add it yourself.

- **Cache hit (the fast path).** `IDekManager.GetActiveDekAsync` and
  `GetDekByWrappedKeyAsync` return a completed `ValueTask<Dek>` with no state-machine
  allocation. The only heap allocation on a hit is the clone of the `byte[] Key` (lesson
  L3 — the cache must not hand out the same array to every caller, otherwise one caller's
  `CryptographicOperations.ZeroMemory` corrupts the cache for the next one).
- **Cache miss.** The call falls through to a private async path that unwraps through
  `IKeyEncryptionProvider` and populates the cache on success. The cost is dominated by
  the KEK round-trip — for HashiCorp Vault this is typically 1–10 ms over localhost and
  10–100 ms over WAN.
- **TTL tuning.** `VellumOptions.DekCacheTtl` defaults to 30 minutes. Shorter TTLs reduce
  the window during which a plaintext DEK is live in process memory, at the cost of more
  frequent KEK round-trips. Longer TTLs improve throughput but increase the exposure
  window. Set to `TimeSpan.Zero` to disable caching entirely — useful in unit tests that
  want to count KEK calls, and in production if your threat model forbids any in-process
  key material longevity.

Published benchmarks will land alongside Sprint 2 of the documentation; until then, the
empirical observation from the early-adopter dogfood is that "10 consecutive decrypts of
the same envelope incur at most 1 KEK unwrap" (verified by a test that counts calls on a
decorating `IKeyEncryptionProvider`).

## What TFMs does Vellum target?

All shipped packages multi-target `net8.0`, `net9.0`, and `net10.0`. The test suite runs
against `net10.0` by default; compile-only runs verify `net8.0` and `net9.0` also build
with zero warnings under `TreatWarningsAsErrors`.

- **`net8.0`** is the current long-term support release of .NET.
- **`net9.0`** is the current STS release.
- **`net10.0`** is the upcoming LTS at the time of writing.

Vellum will drop a TFM **only when it goes out of Microsoft support**, not when a new one
ships. Consumers on `net8.0` (LTS) will always get Vellum updates until `net8.0`'s own
end-of-support date in November 2026.

There is intentionally no `netstandard2.0` target. Vellum uses `Span<byte>`,
`CryptographicOperations.ZeroMemory(Span<byte>)`, `Random​Number​Generator​.Fill`, primary
constructors, `LoggerMessage` source generators, and several other features that do not
compile back to netstandard2.0 without hacks. The minimum is `net8.0`.

## Why do I need the `[VellumEntityFrameworkOptions]` attribute?

`dotnet ef migrations add` prefers an `IDesignTimeDbContextFactory<T>` over building the
host when both are available. A factory that calls `UseNpgsql` but forgets `UseVellum`
produces `DbContextOptions` without the Vellum options extension, and the scaffolder falls
back to Vellum defaults (PascalCase column names, SQL Server filter syntax) silently —
even if the runtime `AddDbContext` pipeline is configured correctly.

An early-adopter backend hit this exact bug while trying to adopt snake_case column
overrides in iteration 2 of their dogfood. The fix is the `[VellumEntityFrameworkOptions]`
attribute (issue [#17](https://github.com/OkaySire/vellum/issues/17)). Decorate your `DbContext` class with
it, list the overrides you want, and Vellum's model builder extension reads the attribute
via reflection at both runtime and design time — so the scaffolded migration always
matches the runtime schema, regardless of which code path the tooling took.

Resolution order for `VellumEntityFrameworkOptions`, from highest to lowest priority:

1. `UseVellum(...)` on the `DbContextOptionsBuilder` (explicit, per-context).
2. `[VellumEntityFrameworkOptions]` attribute on the `DbContext` class (reflection-readable
   at both runtime and design time — this is what survives the scaffolder).
3. `IOptions<VellumEntityFrameworkOptions>` from the application service provider.
4. Defaults (`vellum_encryption_keys` PascalCase + SQL Server filter).

See the [`VellumEntityFrameworkOptionsAttribute` source](../src/Vellum.EntityFrameworkCore/VellumEntityFrameworkOptionsAttribute.cs)
for the attribute-level XML docs, or the [top-level README](../README.md) for the full
example block.

## What's the plan for Azure Key Vault / AWS KMS / GCP KMS support?

All three cloud providers are planned for **`0.3.0`**. The interface
(`IKeyEncryptionProvider.WrapAsync` / `UnwrapAsync` / `RewrapAsync`) is already stable;
implementing a new provider is a few hundred lines of code plus options / DI extensions /
validator and a test project. (`RewrapAsync` can be implemented as unwrap-then-wrap with
the intermediate plaintext zeroed — see `Vellum.Static` — when the backend has no native
rewrap operation.)

If you need one of these providers today, you have two options:

1. **Wait for `0.3.0`.** No ETA yet; the release is gated on time availability rather than
   technical blockers.
2. **Implement it yourself against the interface.** Take
   [`src/Vellum.Vault/VaultKeyEncryptionProvider.cs`](../src/Vellum.Vault/VaultKeyEncryptionProvider.cs)
   as the reference and replace the Vault Transit HTTP calls with your cloud SDK calls.
   Register it via `services.TryAddSingleton<IKeyEncryptionProvider, YourProvider>()` (or
   Transient if you are bridging from a typed `HttpClient` — see
   [lesson L16 in the architecture doc](architecture.md#where-to-find-lesson-references)).

A contribution upstream of any of these providers is very welcome.

## How do I report a security vulnerability?

Please follow the process in
[`SECURITY.md`](https://github.com/OkaySire/vellum/blob/main/SECURITY.md) at the top of the
repository. In brief: use private vulnerability reporting via the GitHub UI
(`Security → Report a vulnerability`) rather than filing a public issue. The Vellum
maintainers acknowledge reports within one business day and will coordinate a fix + CVE +
coordinated disclosure timeline directly with you.

Please do **not** file a public issue for security reports — doing so exposes the bug to
every other consumer before a fix is available.

## Does Vellum ship any telemetry or metrics?

**Not yet in Core.** `Vellum.Core` emits structured logs via the `LoggerMessage` source
generators (see any `Log*` method in `DekManager` or `PayloadEncryptor`), which is enough
for a consumer to build its own dashboards, but there are no counters, histograms, or
OpenTelemetry spans shipped today.

Planned for `Vellum.AspNetCore` (a future release):

- OpenTelemetry `Meter` instruments for cache hit rate, KEK round-trip latency, DEK
  creation rate, and rotation events.
- `IHealthCheck` implementations for the KEK provider and the DEK store.
- Activity sources for distributed tracing through wrap/unwrap and encrypt/decrypt.

Until then, the three signals that matter most (cache hit rate, KEK latency, fail-closed
exceptions) can all be derived from the structured logs Vellum emits by default — every
`DekManager` log line includes the scope, the KeyId where relevant, and a stable EventId
that makes SIEM rule authoring straightforward.
