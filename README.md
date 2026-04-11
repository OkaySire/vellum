# Vellum

> **Vellum** _(n.)_ — fine parchment historically used for important documents, charters, and sealed letters. Evokes preservation, authenticity, and secrecy — the core values of envelope encryption.

**Vellum** is a provider-agnostic, production-grade **envelope encryption library for .NET** with DEK lifecycle management, key rotation, and multi-tenant support.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4)](https://dotnet.microsoft.com/)
[![Build & Test](https://github.com/OkaySire/vellum/actions/workflows/build.yml/badge.svg)](https://github.com/OkaySire/vellum/actions/workflows/build.yml)

> **Status: `0.1.0-preview` — Not yet ready for production. API may change.**

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
| `Vellum.Rotation` | Opt-in background DEK rotation _(Phase 4)_. |
| `Vellum.AspNetCore` | DI extensions + health checks _(Phase 4)_. |

## Quickstart

Install the packages (preview — mark `--prerelease`):

```bash
dotnet add package Vellum.Abstractions       --prerelease
dotnet add package Vellum.Core                --prerelease
dotnet add package Vellum.Vault               --prerelease
dotnet add package Vellum.EntityFrameworkCore --prerelease
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
DB round-trip. Since 0.1.0-preview.2, `DecryptAsync` is also backed by an in-memory
cache keyed by the wrapped ciphertext (see [#6](https://github.com/OkaySire/vellum/issues/6)),
so read-heavy workloads pay at most one KEK round-trip per distinct DEK.

For more complete wiring — feature-flagged rollouts, snake_case schemas, migrations
from a legacy encryption layer, `appsettings.json` bridging — see the
[`samples/`](samples/) folder and [`docs/consumer-options-bridging.md`](docs/consumer-options-bridging.md).

## Building locally

Requires the .NET 10 SDK (see `global.json`) plus the .NET 8 and .NET 9 runtimes for running the multi-target test suite.

```bash
dotnet restore --locked-mode
dotnet build -c Release
dotnet test -c Release
```

`--locked-mode` is mandatory: Vellum commits `packages.lock.json` for every project so transitive versions are pinned and auditable. Any drift fails the restore.

## Release process

Releases are manual. The `release.yml` workflow publishes to nuget.org automatically when a GitHub Release is published.

1. Bump `VersionPrefix` / `VersionSuffix` in `Directory.Build.props`.
2. Commit the bump and tag the commit: `git tag v0.1.0-preview.1 && git push --tags`.
3. Create a **GitHub Release** targeting the tag (UI or `gh release create`).
4. The `Release to NuGet` workflow packs all production packages and pushes them (with `.snupkg` symbols) to nuget.org.

The `NUGET_API_KEY` repository secret must be configured (Settings → Secrets and variables → Actions). Without it the workflow still packs and uploads artifacts, but skips the nuget.org publish with a clear warning.

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

## Branch protection

Branch protection on `main` must be configured manually in the GitHub UI (Settings → Branches → Add rule) to require the `build-test` job from `Build & Test` to pass before merge. This cannot be encoded in the workflow YAML.

## License

Apache License 2.0. See [LICENSE](LICENSE).
