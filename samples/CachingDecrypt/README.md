# Vellum — CachingDecrypt (historical tombstone)

> **This sample is a tombstone.** The pattern it documents — a decorator over
> `IPayloadEncryptor` that caches unwrapped DEKs on the decrypt path — became
> obsolete when the cache was baked directly into
> `Vellum.Core` via [#6](https://github.com/OkaySire/vellum/issues/6).

## Why this directory exists

The `jacqcloud-buses` dogfood in Phase 2 surfaced a critical performance gap:
`Vellum.Core.PayloadEncryptor.DecryptAsync` hit the KEK provider (Vault / KMS /
Azure Key Vault) on every decrypt call because the envelope was self-contained —
no DB round-trip, but also no cache. For a read-heavy bus workload that reads the
same envelopes thousands of times, that turned Vault into a per-message latency
source.

The backend team worked around it by writing a custom `VellumBackedPayloadEncryptor`
that cached unwrapped DEKs by `KeyId` via `IMemoryCache`. That custom wrapper was
the "CachingDecrypt" pattern — and this folder was going to ship the canonical
version of it.

## What happened

Vellum added
`IDekManager.GetDekByWrappedKeyAsync(WrappedKey)` which caches unwrapped DEKs keyed
by a SHA-256 hash of the wrapped ciphertext. `Vellum.Core.PayloadEncryptor.DecryptAsync`
now routes through it automatically — consumers get the caching behavior with zero
code changes and without writing a decorator.

As a result, **the CachingDecrypt sample has nothing to demonstrate**. The caching
is on the decrypt path, in `Vellum.Core`, by default, for everyone.

## Can I still use the old pattern?

Technically yes — you can still write an `IPayloadEncryptor` decorator that wraps
`DecryptAsync` and maintains its own cache (e.g. if you need a distributed cache
backed by Redis, or per-tenant TTLs, or telemetry hooks). But before doing that,
measure: the built-in cache uses the shared `IMemoryCache` instance from
`services.AddMemoryCache()` and respects `VellumOptions.DekCacheTtl`, which is
enough for the vast majority of workloads. Prefer configuration over decoration.

## Related

- [#6](https://github.com/OkaySire/vellum/issues/6) — the issue that drove the
  built-in cache change.
- Private lesson L24 — the security reasoning for why the new cache is keyed on
  a hash of the wrapped ciphertext (not on `KeyId`) and why that does not violate
  the L15 scope-partitioning rule for opaque identifiers.
- [`src/Vellum.Core/DekManager.cs`](../../src/Vellum.Core/DekManager.cs) —
  `GetDekByWrappedKeyAsync` implementation.
- [`src/Vellum.Core/PayloadEncryptor.cs`](../../src/Vellum.Core/PayloadEncryptor.cs) —
  the `DecryptAsync` path that calls into it.
