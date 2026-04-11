# Vellum — feature-flagged encryption sample

> Shows how to gate envelope encryption on a consumer-owned feature flag without
> churning the DI container or call sites during a staged rollout.

## Why

`Vellum.Core.PayloadEncryptor.IsEnabled` is hardcoded `true`. A consumer that wants
to roll encryption out gradually (dev → staging → canary prod → full prod) has to
wrap `IPayloadEncryptor` in a decorator that honours a feature flag. This sample is
the reference implementation.

This is the issue [#11](https://github.com/OkaySire/vellum/issues/11) workaround
until a built-in toggle lands in 0.2.0 or later.

## What the decorator does

`FeatureFlaggedPayloadEncryptor` is a thin decorator over any `IPayloadEncryptor`:

1. On `EncryptAsync`:
   - **Flag ON**: delegates to the inner encryptor → real AES-GCM envelope.
   - **Flag OFF**: returns a **sentinel envelope** whose `WrappedDek.ProviderVersion`
     equals `"vellum-sample:passthrough"` and whose `Ciphertext` carries the raw
     plaintext.
2. On `DecryptAsync`:
   - Checks for the `"vellum-sample:passthrough"` sentinel and returns the raw
     plaintext if found; otherwise delegates to the inner encryptor.

This lets you flip encryption on and off without changing any call site, at the cost
of slightly unusual on-disk data when the flag is off. The alternative is to
**throw** when the flag is off, forcing every call site to check the flag first.
Pick whichever matches your rollout strategy — the decorator is ~40 lines either way.

## Running locally

```bash
dotnet run --project samples/FeatureFlagged
```

Expected output:

```text
Vellum feature-flagged encryption sample
========================================

[ON] ciphertext-length=34, nonce-length=12, provider=v1
[ON] decrypted: "hello from flag-ON"

[OFF] ciphertext-length=19, nonce-length=0, provider=vellum-sample:passthrough
[OFF] decrypted: "hello from flag-OFF"

Sample completed.
```

The flag-ON run produces a real 34-byte ciphertext + 12-byte nonce + `"v1"` wrapped
provider version. The flag-OFF run produces a 19-byte ciphertext (the 19 bytes of
`"hello from flag-OFF"`), zero-length nonce, and the passthrough marker.

## Wiring into a real DI container

The sample constructs the decorator by hand for clarity. In a real app, use
[Scrutor](https://www.nuget.org/packages/Scrutor) for zero-boilerplate decoration:

```csharp
services.Configure<FeatureFlags>(configuration.GetSection("FeatureFlags"));

services.AddVellum();
services.AddVaultProvider(opts => { /* ... */ });
services.AddEntityFrameworkCoreStore<AppDbContext>();

// One line with Scrutor:
services.Decorate<IPayloadEncryptor, FeatureFlaggedPayloadEncryptor>();
```

Without Scrutor, you can decorate manually by locating the existing
`IPayloadEncryptor` `ServiceDescriptor` and replacing it with a factory that builds
the decorator around the original descriptor's factory/type.

## Hot-reload

The decorator takes `IOptionsMonitor<FeatureFlags>`, so an `appsettings.json` change
or a remote flag store push flips the flag mid-process without a restart. The sample
uses a trivial `StaticOptionsMonitor<T>` for brevity; a real app would rely on the
built-in `IOptionsMonitor<T>` registered by `services.Configure<FeatureFlags>(...)`.

## Caveats and production notes

- **The passthrough envelope is NOT encrypted.** Database dumps of rows written while
  the flag was off contain the raw plaintext. Think hard about whether your threat
  model accepts that before shipping the passthrough variant; if it doesn't, use the
  throw-on-disabled variant instead.
- **Historical mixing.** Any envelope written while the flag was ON stays encrypted
  forever — `DecryptAsync` will still use the real encryptor for those rows because
  the sentinel check doesn't fire. Data written before and after a flag flip coexists
  cleanly.
- **Never use `Vellum.Static` in production.** The sample uses it so it has no external
  dependencies. Your real KEK provider is `Vellum.Vault` or one of the cloud providers
  once Phase 3 ships.
