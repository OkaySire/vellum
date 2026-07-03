# Getting started

> **Goal.** Zero to a working encrypt/decrypt round-trip in 15 minutes, then upgrade the same
> project to a realistic Vault + PostgreSQL stack without rewriting any business code.

This guide walks through four progressive stages:

1. [A 20-line console app using `Vellum.Static` and `Vellum.InMemory`](#1-dev-first-console-app)
2. [Upgrade to a real KEK with `Vellum.Vault`](#2-upgrade-to-a-real-kek-with-vellumvault)
3. [Add persistent DEK storage with `Vellum.EntityFrameworkCore`](#3-persistent-storage-with-ef-core)
4. [Pick a scope convention for multi-tenancy and rotation](#4-scope-and-rotation)

Each stage is independently runnable. If you only need the dev-first setup for a spike or a
unit test, stop after stage 1.

## Prerequisites

- **.NET SDK**. Vellum targets `net8.0`, `net9.0`, and `net10.0`. This guide assumes
  `net10.0`; the commands are the same on earlier TFMs.
- **A terminal with `dotnet` on the PATH**. No IDE required, but any will work.
- **Docker** (stages 2 and 3 only) — used to run a HashiCorp Vault dev server and a
  PostgreSQL container. If you already have a Vault instance and a Postgres database,
  skip the Docker bits and point at yours.

> Vellum is published to nuget.org. Install commands below use `dotnet add package`
> without any prerelease flag.

## 1. Dev-first console app

We start with the simplest possible working Vellum app — a console program that uses the
**static KEK** (an in-process Key Encryption Key loaded from config) and the **in-memory
DEK store** (a process-local dictionary of wrapped DEKs). No Vault, no database, no
containers.

> **Warning.** `Vellum.Static` is dev-only. It stores the KEK in process memory bootstrapped
> from configuration — a process dump, leaked config file, or environment-variable dump equals
> a complete compromise of every DEK wrapped by it. Never use `Vellum.Static` in production.
> Stage 2 swaps it out for HashiCorp Vault Transit; stages 3–4 assume a real provider.

### 1.1 Create the project

```bash
mkdir vellum-quickstart && cd vellum-quickstart
dotnet new console -f net10.0
dotnet add package Vellum.Core     dotnet add package Vellum.Static   dotnet add package Vellum.InMemory dotnet add package Microsoft.Extensions.Logging.Console
```

You do not need to reference `Vellum.Abstractions` explicitly — `Vellum.Core` brings it in as
a transitive dependency.

### 1.2 Replace `Program.cs`

```csharp
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Vellum;
using Vellum.InMemory;
using Vellum.Static;

// Generate a throwaway dev KEK. Never ship anything like this.
byte[] devKekBytes = new byte[32];
RandomNumberGenerator.Fill(devKekBytes);
string devKekBase64 = Convert.ToBase64String(devKekBytes);

ServiceCollection services = new();
services.AddLogging(b => b.AddConsole().SetMinimumLevel(LogLevel.Information));
services.AddVellum();                                   // registers IDekManager, IPayloadEncryptor
services.AddStaticProvider(o => o.Base64Key = devKekBase64); // registers IKeyEncryptionProvider (dev-only!)
services.AddInMemoryStore();                            // registers IEncryptionKeyStore

await using ServiceProvider provider = services.BuildServiceProvider();
IPayloadEncryptor encryptor = provider.GetRequiredService<IPayloadEncryptor>();

EncryptedPayload envelope = await encryptor.EncryptStringAsync(
    plaintext: "hello from Vellum",
    scope: "tenant:demo");

Console.WriteLine($"KeyId:      {envelope.KeyId}");
Console.WriteLine($"Ciphertext: {envelope.Ciphertext.Length} bytes (plaintext + 16-byte AES-GCM tag)");
Console.WriteLine($"Nonce:      {envelope.Nonce.Length} bytes");
Console.WriteLine($"Provider:   {envelope.WrappedDek.ProviderVersion}");

// Decryption requires the same scope: envelopes are scope-bound by default
// (format version 2 — the scope is baked into the AES-GCM associated data).
string roundtrip = await encryptor.DecryptStringAsync(envelope, scope: "tenant:demo");
Console.WriteLine();
Console.WriteLine($"Decrypted:  \"{roundtrip}\"");
```

### 1.3 Run it

```bash
dotnet run
```

Expected output (the `KeyId` will differ on your machine):

```text
warn: Vellum.Static.StaticKeyEncryptionProvider[1]
      ⚠ Vellum.Static KEK provider active — DEVELOPMENT USE ONLY. Never use this
      provider in production. Data encrypted with the static KEK has the same
      security as the config source it came from.
KeyId:      3ff14ab1-c61f-4a3e-9a0e-1f8cabde5b6a
Ciphertext: 33 bytes (plaintext + 16-byte AES-GCM tag)
Nonce:      12 bytes
Provider:   v1
Decrypted:  "hello from Vellum"
```

The loud warning on the first wrap is intentional — `Vellum.Static` emits it exactly once per
process so a dev-only provider cannot accidentally ship to production without leaving a
trace in the logs. See [FAQ — Why does `Vellum.Static` exist?](faq.md#why-does-vellumstatic-exist-and-when-should-i-use-it).

### 1.4 What just happened

Three services were wired into DI:

- **`IKeyEncryptionProvider`** (implementation: `StaticKeyEncryptionProvider`). Wraps and
  unwraps DEKs with an AES-256-GCM KEK loaded from config.
- **`IEncryptionKeyStore`** (implementation: `InMemoryEncryptionKeyStore`). Holds wrapped
  DEKs in a process-local concurrent dictionary.
- **`IDekManager`** and **`IPayloadEncryptor`** (from `AddVellum()`). The manager coordinates
  the provider and store; the encryptor is the high-level API your code calls.

On `EncryptStringAsync`, Vellum:

1. Resolved the **active DEK for scope `tenant:demo`**. None existed, so it:
   - generated a fresh 256-bit AES key with `RandomNumberGenerator`,
   - called `WrapAsync` on the static provider to produce a wrapped blob,
   - persisted the wrapped blob in the in-memory store,
   - cached the unwrapped DEK so the next encrypt for the same scope is a lock-free
     dictionary lookup.
2. Generated a 12-byte AES-GCM nonce.
3. Encrypted the UTF-8 bytes of `"hello from Vellum"` with `AesGcm`, binding the scope into
   the AES-GCM associated data (envelope format version 2, the default — see
   `VellumOptions.BindScopeToCiphertext`).
4. Zeroed the plaintext DEK bytes in a `finally` block.
5. Returned a self-contained `EncryptedPayload` carrying the ciphertext, nonce, wrapped DEK,
   audit `KeyId`, and `FormatVersion`.

On `DecryptStringAsync`, Vellum read the wrapped DEK directly off the envelope, unwrapped it
once, cached the result keyed on a hash of the wrapped ciphertext (see
[architecture — memory hygiene](architecture.md#memory-hygiene) and lesson L24 in the FAQ for
why this is safe without scope-partitioning), reconstructed the scope associated data from
the scope you passed (a wrong or missing scope fails the authentication tag check — that is
the multi-tenant envelope-swap defence), ran AES-GCM in decrypt mode, and returned the UTF-8
string.

## 2. Upgrade to a real KEK with `Vellum.Vault`

A production KEK must live outside your process. We swap `Vellum.Static` for
`Vellum.Vault`, which talks to the HashiCorp Vault Transit secrets engine over HTTPS.

### 2.1 Run a Vault dev server locally

```bash
docker run -d --name vellum-vault \
    -p 127.0.0.1:8200:8200 \
    -e VAULT_DEV_ROOT_TOKEN_ID=dev-root \
    --cap-add IPC_LOCK \
    hashicorp/vault:latest
```

Wait a few seconds, then enable the Transit engine and create a key:

```bash
curl -sf -X POST \
    -H "X-Vault-Token: dev-root" \
    http://127.0.0.1:8200/v1/sys/mounts/transit \
    -d '{"type":"transit"}'

curl -sf -X POST \
    -H "X-Vault-Token: dev-root" \
    http://127.0.0.1:8200/v1/transit/keys/vellum-quickstart-kek \
    -d '{}'
```

> **dev-root is not a real token.** Vault's `-dev` mode is only for local use. Production
> tokens come from an auth method — Kubernetes, AppRole, JWT, cert, … — and are never
> pasted into a shell. `Vellum.Vault` supports **AppRole natively** and it is the
> recommended production auth method: see [§2.4](#24-how-vault-options-should-flow-in-a-real-app).

### 2.2 Swap the provider package

```bash
dotnet remove package Vellum.Static
dotnet add    package Vellum.Vault ```

### 2.3 Update `Program.cs`

Replace the `AddStaticProvider` call with `AddVaultProvider`:

```csharp
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Vellum;
using Vellum.InMemory;
using Vellum.Vault;

ServiceCollection services = new();
services.AddLogging(b => b.AddConsole().SetMinimumLevel(LogLevel.Information));

services.AddVellum(opts => opts.DekCacheTtl = TimeSpan.FromMinutes(30));

services.AddVaultProvider(opts =>
{
    opts.Address = "http://127.0.0.1:8200";
    opts.AllowInsecureHttp = true;      // ← dev server only. Plain http:// is rejected by
                                        //   default because it sends the token and plaintext
                                        //   DEKs in cleartext. NEVER enable in production.
    opts.Token   = "dev-root";          // ← load from a secret store in real code
    opts.KeyName = "vellum-quickstart-kek";
});

services.AddInMemoryStore();            // still in-memory for now; stage 3 adds persistence

await using ServiceProvider provider = services.BuildServiceProvider();
IPayloadEncryptor encryptor = provider.GetRequiredService<IPayloadEncryptor>();

EncryptedPayload envelope = await encryptor.EncryptStringAsync("hello from Vault", "tenant:demo");
string roundtrip          = await encryptor.DecryptStringAsync(envelope, "tenant:demo");

Console.WriteLine($"Provider version: {envelope.WrappedDek.ProviderVersion}"); // e.g. "v1"
Console.WriteLine($"Decrypted:        \"{roundtrip}\"");
```

Run it: the only visible difference is that `envelope.WrappedDek.ProviderVersion` now comes
from Vault (`v1`, or `v2` and up if you have rotated the Transit key), and the startup warning
from `Vellum.Static` is gone.

### 2.4 How Vault options should flow in a real app

The snippet above hard-codes `Token = "dev-root"` for brevity. A real app binds
`VaultOptions` to `appsettings.json` or a secret store. See
[consumer options bridging](consumer-options-bridging.md) for the pattern — the short
version is `services.AddOptions<VaultOptions>().Configure<IOptions<YourEncryptionOptions>>(...)`,
and you should **never** call `services.BuildServiceProvider()` inside a `Configure` delegate.

For production, prefer **AppRole** authentication over a static token. A fixed periodic
token that expires causes a silent outage; AppRole tokens are re-acquired automatically
(a fresh login fires once the cached token passes `TokenRenewalThreshold`, 80 % of its
lease by default, and a `403` triggers an immediate re-login plus one retry):

```csharp
services.AddVaultProvider(opts =>
{
    opts.Address    = "https://vault.example.com:8200";
    opts.AuthMethod = VaultAuthMethod.AppRole;
    opts.RoleId     = configuration["Vault:RoleId"]!;    // from a secret store
    opts.SecretId   = configuration["Vault:SecretId"]!;  // from a secret store
    opts.KeyName    = "vellum-quickstart-kek";
});
```

Every Vault request also goes through the standard HTTP resilience handler by default
(retries on transient failures, timeouts derived from `VaultOptions.HttpTimeout`); set
`EnableResilience = false` inside the `AddVaultProvider` delegate to opt out.

## 3. Persistent storage with EF Core

`Vellum.InMemory` loses every wrapped DEK on process restart, which is fine for tests and
samples but not for any real deployment. Stage 3 moves the DEK storage to PostgreSQL via
`Vellum.EntityFrameworkCore` and `Npgsql.EntityFrameworkCore.PostgreSQL`.

### 3.1 Run a Postgres container

```bash
docker run -d --name vellum-postgres \
    -p 127.0.0.1:5432:5432 \
    -e POSTGRES_USER=vellum \
    -e POSTGRES_PASSWORD=vellum \
    -e POSTGRES_DB=vellum_quickstart \
    postgres:16-alpine
```

### 3.2 Install EF packages

```bash
dotnet remove package Vellum.InMemory
dotnet add    package Vellum.EntityFrameworkCore      dotnet add    package Microsoft.EntityFrameworkCore   --version 10.*
dotnet add    package Npgsql.EntityFrameworkCore.PostgreSQL --version 10.*
```

### 3.3 Define a `DbContext`

Create `AppDbContext.cs`:

```csharp
using Microsoft.EntityFrameworkCore;
using Vellum.EntityFrameworkCore;

namespace VellumQuickstart;

[VellumEntityFrameworkOptions(
    TableName = "vellum_encryption_keys",
    UniqueActiveIndexFilter = "\"IsActive\" = true")] // PostgreSQL syntax — see §3.6
public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        base.OnModelCreating(modelBuilder);

        // Reads VellumEntityFrameworkOptions from:
        //   1. UseVellum(...) on the options builder, else
        //   2. the [VellumEntityFrameworkOptions] attribute above, else
        //   3. IOptions<VellumEntityFrameworkOptions> in DI, else
        //   4. defaults.
        modelBuilder.AddVellumEncryptionKeys(this);
    }
}
```

> **Why the attribute?** Without it, `dotnet ef migrations add` builds the context via a
> slightly different path than your `Program.cs`, and the scaffolder may not see the Vellum
> options you attached via `UseVellum`. The attribute is reflection-readable at both runtime
> and design time, so the scaffolded migration always matches the runtime schema. This is
> issue #17 in the repo. See the [FAQ](faq.md#why-do-i-need-the-vellumentityframeworkoptions-attribute).

### 3.4 Rewire `Program.cs`

```csharp
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Vellum;
using Vellum.EntityFrameworkCore;
using Vellum.Vault;
using VellumQuickstart;

ServiceCollection services = new();
services.AddLogging(b => b.AddConsole().SetMinimumLevel(LogLevel.Information));

services.AddDbContext<AppDbContext>(options => options
    .UseNpgsql("Host=127.0.0.1;Port=5432;Database=vellum_quickstart;Username=vellum;Password=vellum"));

services.AddVellum(opts => opts.DekCacheTtl = TimeSpan.FromMinutes(30));
services.AddVaultProvider(opts =>
{
    opts.Address = "http://127.0.0.1:8200";
    opts.AllowInsecureHttp = true;      // dev server only — never in production
    opts.Token   = "dev-root";
    opts.KeyName = "vellum-quickstart-kek";
});
services.AddEntityFrameworkCoreStore<AppDbContext>();

await using ServiceProvider provider = services.BuildServiceProvider();

// Create the schema. In real apps, use dotnet ef migrations instead — EnsureCreated
// is fine for a first-run quickstart.
using (IServiceScope scope = provider.CreateScope())
{
    AppDbContext ctx = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await ctx.Database.EnsureCreatedAsync();
}

// Encrypt / decrypt inside a DI scope so the scoped DbContext + store resolve correctly.
using (IServiceScope scope = provider.CreateScope())
{
    IPayloadEncryptor encryptor = scope.ServiceProvider.GetRequiredService<IPayloadEncryptor>();

    EncryptedPayload envelope = await encryptor.EncryptStringAsync("persisted in postgres", "tenant:demo");
    string roundtrip          = await encryptor.DecryptStringAsync(envelope, "tenant:demo");

    Console.WriteLine($"Persisted KeyId:  {envelope.KeyId}");
    Console.WriteLine($"Decrypted:        \"{roundtrip}\"");
}
```

Run `dotnet run` and then inspect the database to see the wrapped DEK:

```bash
docker exec -it vellum-postgres psql -U vellum -d vellum_quickstart \
    -c 'SELECT "KeyId", "Scope", "WrappedProviderVersion", "IsActive" FROM vellum_encryption_keys;'
```

You should see exactly one row, marked active, with `WrappedProviderVersion = 'v1'`.

### 3.5 Lifetime notes

- `AddVellum()` registers `IDekManager` and `IPayloadEncryptor` as **Scoped** so they can
  transitively depend on a scoped `DbContext`. Always resolve `IPayloadEncryptor` inside a DI
  scope; in an ASP.NET Core app the per-request scope handles this automatically.
- `AddEntityFrameworkCoreStore<TContext>()` registers the store as **Scoped** for the same
  reason.
- `AddVaultProvider()` registers `VaultKeyEncryptionProvider` as **Transient** (the default
  for `AddHttpClient<TClient>`) so that `IHttpClientFactory` can rotate the underlying
  `HttpMessageHandler`. This is load-bearing — see lesson L16 and
  [FAQ — What happens if a KEK provider is temporarily unavailable?](faq.md#what-happens-if-a-kek-provider-is-temporarily-unavailable).

### 3.6 The per-provider index filter

`VellumEntityFrameworkOptions.UniqueActiveIndexFilter` is a raw SQL fragment used by the
"only one active key per scope" filtered unique index. Every EF Core provider spells it
differently:

| Provider | `UniqueActiveIndexFilter` value |
|---|---|
| SQL Server (default) | `[IsActive] = 1` |
| PostgreSQL (Npgsql) | `"IsActive" = true` |
| SQLite | `"IsActive" = 1` |
| MySQL (Pomelo) | not supported — filtered indexes aren't available, use a non-filtered composite uniqueness check |

Set this via the `[VellumEntityFrameworkOptions]` attribute (recommended for compile-time
schemas), `UseVellum` on the `DbContextOptionsBuilder`, or
`AddEntityFrameworkCoreStore<T>(o => ...)` for DI-only configuration.

## 4. Scope and rotation

### 4.1 Pick a scope convention

Vellum never interprets the `scope` string. It is an opaque partition key used for:

- cache keys (`vellum:dek:active:{scope}`),
- store queries (`WHERE scope = @scope`),
- multi-tenant defence on `GetDekByKeyIdAsync` (a caller asking for a specific `KeyId` must
  also prove they know the scope it lives in — see lesson L15).

The **convention you pick defines your blast radius on a KEK compromise or a DEK cache
eviction**. Pick a convention that matches the tenant boundary of your data:

| Data boundary | Example scope strings |
|---|---|
| One tenant per customer | `tenant:3fbe9c40-...` |
| One bus / message namespace per workspace | `bus:workspace-42` |
| Per-user encryption (rare) | `user:alice@example.com` |
| Global (single-tenant app) | `global` |

The scope must be stable across encrypt and decrypt for the same data, so avoid using
anything that can change — for example, user display names.

### 4.2 Rotate a DEK

`IDekManager.RotateDekAsync(scope)` generates and wraps a fresh DEK first, then atomically
swaps it in as the scope's active key (deactivate-old + insert-new in a single
transaction); if the KEK provider or the store fails mid-rotation, the old key stays
active. Historical envelopes stay decryptable because `EncryptedPayload` carries its own
`WrappedDek` — rotation is a write-path operation only, it does not re-encrypt any
existing data.

```csharp
using (IServiceScope scope = provider.CreateScope())
{
    IDekManager dekManager = scope.ServiceProvider.GetRequiredService<IDekManager>();

    // Any payloads encrypted BEFORE this call still decrypt via their embedded WrappedDek.
    // Any payloads encrypted AFTER this call use the fresh DEK.
    await dekManager.RotateDekAsync("tenant:demo");
}
```

`RotateDekAsync` does **not** need to be on a schedule — you can call it from a controller
(e.g. in response to a "rotate now" admin action) or from a background job. For scheduled
rotation, add the opt-in **`Vellum.Rotation`** package and register the hosted worker:

```csharp
services.AddVellumRotation(o =>
{
    o.RotationInterval = TimeSpan.FromHours(24); // how often the worker ticks
    o.MaxDekAge        = TimeSpan.FromHours(24); // rotate only keys at least this old
});
```

See the [key rotation runbook](kek-rotation.md) for the full operational picture, and
[FAQ — How do I rotate DEKs without downtime?](faq.md#how-do-i-rotate-deks-without-downtime)
for the failure semantics.

### 4.3 Decrypt a historical envelope

If you have stored envelopes from before a rotation, nothing changes — `DecryptStringAsync`
reads the embedded `WrappedDek` from the envelope and unwraps it through the KEK provider.
No store round-trip, no version matching:

```csharp
// Stored ciphertext + nonce + wrapped-DEK blob + format version somewhere:
EncryptedPayload historical = /* reconstruct from your DB columns */;
string plaintext = await encryptor.DecryptStringAsync(historical, "tenant:demo");
```

> **Persist `FormatVersion`.** If you store envelopes field-by-field (one column per
> `EncryptedPayload` field), persist `FormatVersion` alongside the other columns and
> restore it verbatim — decryption rejects unknown versions fail-closed. Rows persisted
> before Vellum 0.2.0 have no stored version; reconstructing them with the original four
> positional arguments defaults to format version 1 (the legacy unbound layout), which is
> correct and decrypts under any scope argument.

If you need to iterate over **all** historical DEKs for a scope (for example, for an auditor
who wants to list every key ever used), call
`IEncryptionKeyStore.GetHistoricalAsync(scope)` — it returns every `EncryptionKey` record
for the scope, active or inactive, ordered most-recent first.

## Next steps

- Read [Architecture](architecture.md) to see the diagrams for the DEK lifecycle and the
  4-layer race defence on creation.
- Read [Comparison](comparison.md) if you are evaluating Vellum against
  `Microsoft.AspNetCore.DataProtection`, AWS Encryption SDK, or Google Tink.
- If you already have a hand-rolled envelope encryption layer in production, skip to
  [Migrating from a custom implementation](migrations/from-custom.md).
- Questions we hear a lot live in the [FAQ](faq.md).
