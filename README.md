# Vellum

> **Vellum** _(n.)_ — fine parchment historically used for important documents, charters, and sealed letters. Evokes preservation, authenticity, and secrecy — the core values of envelope encryption.

**Vellum** is a provider-agnostic, production-grade **envelope encryption library for .NET** with DEK lifecycle management, key rotation, and multi-tenant support.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4)](https://dotnet.microsoft.com/)
[![Build & Test](https://github.com/OkaySire/vellum/actions/workflows/build.yml/badge.svg)](https://github.com/OkaySire/vellum/actions/workflows/build.yml)

> **Status: `0.2.0` — Pre-1.0 (API may evolve, breaking changes allowed per semver; see [CHANGELOG](CHANGELOG.md) for the 0.2.0 breaking changes). Production use is supported but cloud KMS providers (Azure Key Vault, AWS KMS, GCP KMS) are planned for 0.3.0.**

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
| `Vellum.Rotation` | Opt-in background DEK rotation hosted service. |
| `Vellum.AspNetCore` | DI extensions + health checks _(Phase 4)_. |

## Quickstart

Install the packages:

```bash
dotnet add package Vellum.Abstractions
dotnet add package Vellum.Core
dotnet add package Vellum.Vault
dotnet add package Vellum.EntityFrameworkCore
```

Wire Vellum into an ASP.NET Core / generic host app. Options for the EF Core store
flow via `UseVellum` on the `DbContextOptionsBuilder` — configure them once, no duplication:

```csharp
// Program.cs
services.AddVellum(o => o.DekCacheTtl = TimeSpan.FromMinutes(30));
services.AddVaultProvider(o =>
{
    o.Address = "http://vault:8200";
    o.Token   = builder.Configuration["Vault:Token"]!;
    o.KeyName = "my-kek";
});
services.AddDbContext<AppDbContext>(options => options
    .UseNpgsql(builder.Configuration.GetConnectionString("App"))
    .UseVellum(v => v.UniqueActiveIndexFilter = "\"IsActive\" = true"));
services.AddEntityFrameworkCoreStore<AppDbContext>();

// AppDbContext.cs
public sealed class AppDbContext(DbContextOptions<AppDbContext> opts) : DbContext(opts)
{
    protected override void OnModelCreating(ModelBuilder mb)
    {
        base.OnModelCreating(mb);
        mb.AddVellumEncryptionKeys(this);
    }
}

// Usage (inject IPayloadEncryptor anywhere)
EncryptedPayload envelope = await encryptor.EncryptStringAsync("hello", scope: "tenant:42");
string roundtrip          = await encryptor.DecryptStringAsync(envelope);
```

The envelope carries its own wrapped DEK, so decryption is self-contained — no second
DB round-trip. `DecryptAsync` is backed by an in-memory cache keyed by the wrapped
ciphertext (see [#6](https://github.com/OkaySire/vellum/issues/6)), so read-heavy
workloads pay at most one KEK round-trip per distinct DEK.

For more complete wiring — feature-flagged rollouts, snake_case schemas, migrations
from a legacy encryption layer, `appsettings.json` bridging — see the
[`samples/`](samples/) folder and [`docs/consumer-options-bridging.md`](docs/consumer-options-bridging.md).

### Background DEK rotation (`Vellum.Rotation`)

Rotation is opt-in — `Vellum.Core` never starts a background service. Add the
`Vellum.Rotation` package and register the worker:

```csharp
services.AddVellumRotation(o =>
{
    o.RotationInterval   = TimeSpan.FromHours(24); // how often the worker ticks
    o.MaxDekAge          = TimeSpan.FromHours(24); // rotate only keys at least this old
    o.MaxRetriesPerScope = 3;                      // retry with backoff inside the tick
});
```

Each tick rotates only the scopes whose active DEK has reached `MaxDekAge`; transient
KEK-provider failures are retried per scope with exponential backoff and jitter inside
the tick, and a failed scope never blocks the others. Rotation is fail-safe: if the KEK
provider fails mid-rotation, the previous key stays active. For the full operational
picture — including KEK rotation on the Vault side and the `min_decryption_version`
hazard — see the [key rotation runbook](docs/kek-rotation.md).

### Design-time scaffolder (`dotnet ef migrations add`)

`dotnet ef` prefers an `IDesignTimeDbContextFactory<T>` over the host-build path when
both are available. A factory that forgets to call `UseVellum(...)` produces
`DbContextOptions` without the Vellum options extension, so the scaffolder generates a
migration against Vellum's defaults (PascalCase column names, SQL Server filter
syntax) even if the runtime `AddDbContext` pipeline is configured correctly.
This is [issue #17](https://github.com/OkaySire/vellum/issues/17).

The recommended fix is to declare the Vellum schema once on
the `DbContext` class with `[VellumEntityFrameworkOptions]`. The attribute is
reflection-readable at both runtime and design time, so the scaffolder picks up the
overrides with no duplication between `Program.cs` and the factory:

```csharp
[VellumEntityFrameworkOptions(
    TableName = "bus_encryption_keys",
    KeyIdColumnName = "key_id",
    ScopeColumnName = "scope",
    WrappedCiphertextColumnName = "wrapped_ciphertext",
    WrappedProviderVersionColumnName = "wrapped_provider_version",
    CreatedAtColumnName = "created_at",
    ExpiresAtColumnName = "expires_at",
    IsActiveColumnName = "is_active",
    UniqueActiveIndexFilter = "\"is_active\" = true")]
public sealed class AppDbContext(DbContextOptions<AppDbContext> opts) : DbContext(opts)
{
    protected override void OnModelCreating(ModelBuilder mb)
    {
        base.OnModelCreating(mb);
        mb.AddVellumEncryptionKeys(this);
    }
}
```

The attribute resolution order is: (1) `UseVellum(...)` on the options builder, (2)
`[VellumEntityFrameworkOptions]` on the context type, (3)
`IOptions<VellumEntityFrameworkOptions>` from the application service provider, (4)
defaults. Every attribute property the consumer leaves unset keeps the Vellum
default, so a minimal decoration like
`[VellumEntityFrameworkOptions(TableName = "bus_encryption_keys")]` is valid.

As an alternative, an `IDesignTimeDbContextFactory<T>` can call `UseVellum(...)`
explicitly alongside the provider extension:

```csharp
public sealed class AppDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args)
    {
        DbContextOptionsBuilder<AppDbContext> b = new();
        b.UseNpgsql("Host=localhost;Database=app;Username=postgres;Password=postgres");
        b.UseVellum(v => v.UniqueActiveIndexFilter = "\"IsActive\" = true");
        return new AppDbContext(b.Options);
    }
}
```

Either pattern works. The attribute is cleaner when the Vellum schema is fixed at
compile time; the factory pattern is more flexible when options come from a
configuration source the factory can read directly.

## Building locally

Requires the .NET 10 SDK (see `global.json`) plus the .NET 8 and .NET 9 runtimes for running the multi-target test suite.

```bash
dotnet restore --locked-mode
dotnet build -c Release
dotnet test -c Release
```

`--locked-mode` is mandatory: Vellum commits `packages.lock.json` for every project so transitive versions are pinned and auditable. Any drift fails the restore.

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
