# Bridging consumer options into Vellum options

> **Applies to**: Vellum 0.1.0 and later
> **Source**: feedback from the jacqcloud-buses Phase 2 dogfood migration (section 1 friction #9)

## Problem

Vellum's DI extensions take `Action<TOptions>` delegates:

```csharp
services.AddVellum(opts => { opts.DekCacheTtl = TimeSpan.FromMinutes(30); });
services.AddVaultProvider(opts =>
{
    opts.Address = "http://vault.example:8200";
    opts.Token = "s.XXXX";
    opts.KeyName = "my-kek";
});
services.AddEntityFrameworkCoreStore<AppDbContext>(opts =>
{
    opts.TableName = "encryption_keys";
});
```

But a realistic app keeps its config in an `appsettings.json`-bound POCO, e.g.:

```csharp
public sealed class EncryptionOptions
{
    public string VaultAddress { get; set; } = string.Empty;
    public string VaultToken   { get; set; } = string.Empty;
    public string KeyName      { get; set; } = string.Empty;
    public TimeSpan DekCacheTtl { get; set; } = TimeSpan.FromMinutes(30);
    public string TableName    { get; set; } = "encryption_keys";
}
```

…and `services.Configure<EncryptionOptions>(configuration.GetSection("Encryption"))` is only
fully resolved at **resolve time**, not at **registration time**. So you can't write the
obvious-looking code:

```csharp
// ❌ Broken — EncryptionOptions isn't bound yet at registration time.
EncryptionOptions enc = configuration.GetSection("Encryption").Get<EncryptionOptions>();
services.AddVaultProvider(v => { v.Address = enc.VaultAddress; });
```

And you definitely shouldn't do this:

```csharp
// ❌ Anti-pattern — BuildServiceProvider inside a delegate is a classic DI footgun.
services.AddVaultProvider(v =>
{
    IOptions<EncryptionOptions> opts =
        services.BuildServiceProvider().GetRequiredService<IOptions<EncryptionOptions>>();
    v.Address = opts.Value.VaultAddress;
});
```

`BuildServiceProvider()` inside a delegate creates a disposable root container, leaks
singletons, and breaks validation/scoping guarantees. Don't do it.

## The pattern: deferred `Configure<T>()`

`Microsoft.Extensions.Options` supports a deferred configure overload that takes a dependency
on another `IOptions<T>`. This is the idiomatic way to bridge consumer config into Vellum's
options:

```csharp
// 1. Bind consumer options from configuration.
services.Configure<EncryptionOptions>(builder.Configuration.GetSection("Encryption"));

// 2. Call the Vellum extensions with NO-OP delegates so the typed clients,
//    validators, and DI registrations land in place.
services
    .AddVellum(_ => { })
    .AddVaultProvider(_ => { })
    .AddEntityFrameworkCoreStore<AppDbContext>(_ => { });

// 3. Bridge consumer options into Vellum options via deferred Configure<T>().
services.AddOptions<VellumOptions>()
    .Configure<IOptions<EncryptionOptions>>((vellum, consumer) =>
    {
        vellum.DekCacheTtl = consumer.Value.DekCacheTtl;
    });

services.AddOptions<VaultOptions>()
    .Configure<IOptions<EncryptionOptions>>((vault, consumer) =>
    {
        vault.Address = consumer.Value.VaultAddress;
        vault.Token   = consumer.Value.VaultToken;
        vault.KeyName = consumer.Value.KeyName;
    });

services.AddOptions<VellumEntityFrameworkOptions>()
    .Configure<IOptions<EncryptionOptions>>((ef, consumer) =>
    {
        ef.TableName = consumer.Value.TableName;
    });
```

### Why this works

- `AddOptions<T>().Configure<TDep1>(...)` **defers** the configure delegate until the first
  resolution of `IOptions<T>`. By that time, `IOptions<EncryptionOptions>` has been fully
  bound from configuration.
- Multiple `Configure` calls on the same options type compose in registration order, so you
  can keep the no-op `Action<T>` on `AddVellum(_ => { })` and still layer the deferred
  bridge on top.
- No `BuildServiceProvider()` inside a delegate — the DI container stays healthy.

### Why the no-op `AddVellum(_ => { })` is necessary

`AddVellum`, `AddVaultProvider`, and `AddEntityFrameworkCoreStore<T>` do more than
configure options — they register the typed HTTP client, the `IPayloadEncryptor`
implementation, the `IKeyEncryptionProvider` bridge, the store, and the validator.
You still need to call them, but with an empty delegate so the options block stays
open for the deferred `Configure<IOptions<EncryptionOptions>>(...)` to fill in.

## Flowing options into `DbContextOptionsBuilder.UseVellum`

If you prefer to configure the EF Core options on the `DbContextOptionsBuilder` (via
`UseVellum`, see issue #9), you can pull consumer
options from the service provider that `AddDbContext<T>` passes into the options builder:

```csharp
services.Configure<EncryptionOptions>(builder.Configuration.GetSection("Encryption"));

services.AddDbContext<AppDbContext>((sp, options) =>
{
    EncryptionOptions encryption = sp.GetRequiredService<IOptions<EncryptionOptions>>().Value;

    options.UseNpgsql(encryption.ConnectionString);
    options.UseVellum(v =>
    {
        v.TableName = encryption.TableName;
        v.UniqueActiveIndexFilter = "\"IsActive\" = true"; // Npgsql
    });
});
```

This overload of `AddDbContext<T>` receives the service provider directly, so
`IOptions<EncryptionOptions>` is safe to resolve — it is **not** the same foot-gun as
`services.BuildServiceProvider()` inside a registration delegate.

## See also

- [#9](https://github.com/OkaySire/vellum/issues/9) — single-source EF options via
  `UseVellum` on `DbContextOptionsBuilder`
- [#11](https://github.com/OkaySire/vellum/issues/11) — feature-flagged encryption wrapper
  pattern (see `samples/FeatureFlagged`)
- Microsoft docs: [Options pattern — post-configuration and validation](https://learn.microsoft.com/en-us/dotnet/core/extensions/options#options-post-configuration)
