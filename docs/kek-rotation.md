# Key rotation runbook

> **Goal.** An operational guide to rotating keys in a Vellum deployment: what DEK rotation and
> KEK rotation each do, which operations are safe, and the **one Vault knob that can permanently
> destroy data** (`min_decryption_version`) — and why you must not touch it today.

This runbook assumes the HashiCorp Vault Transit provider (`Vellum.Vault`). The DEK-side
sections apply to any KEK provider; the Vault CLI sections are Transit-specific.

## Two rotations, two layers

Envelope encryption has two key layers, and each rotates independently:

| | DEK (Data Encryption Key) | KEK (Key Encryption Key) |
|---|---|---|
| What it encrypts | Your payloads (AES-256-GCM) | The DEKs |
| Where it lives | Wrapped in the key store + inside every `EncryptedPayload` | Inside Vault Transit (never leaves Vault) |
| Who rotates it | **Vellum** — `Vellum.Rotation` or manual `IDekManager.RotateDekAsync(scope)` | **You / Vault** — `vault write -f transit/keys/<name>/rotate` |
| Effect of rotation | New payloads use a new DEK; historical payloads stay decryptable via their embedded wrapped DEK | New wraps use the new KEK version; old wrapped DEKs keep unwrapping against their old version |

Rotating one layer never requires rotating the other. They are routinely rotated on different
schedules (for example, DEKs daily via `Vellum.Rotation`, the KEK quarterly via Vault).

## DEK rotation

### Automatic: `Vellum.Rotation`

```csharp
services.AddVellum();
// ... KEK provider + key store registrations ...
services.AddVellumRotation(options =>
{
    options.RotationInterval = TimeSpan.FromHours(24); // how often the worker ticks
    options.MaxDekAge        = TimeSpan.FromHours(24); // rotate only keys at least this old
});
```

On each tick the worker lists every scope with an active key, **skips scopes whose active key is
younger than `MaxDekAge`** (no pointless KEK round-trips, no churn synchronised onto the tick
schedule), and rotates the rest. Failures are retried per scope with exponential backoff and
jitter *inside the tick* (`MaxRetriesPerScope`, `RetryBaseDelay`), so a transient Vault blip does
not postpone a scope's rotation by a full interval. A scope that exhausts its retries is logged
as an error and the tick moves on — one broken scope never blocks the others.

### Manual

```csharp
await dekManager.RotateDekAsync("tenant:42", cancellationToken);
```

Same machinery, on demand. Useful after a suspected DEK exposure for a specific scope, or for
deployments that prefer an external scheduler over an in-process hosted service.

### What rotation does — and does not — do

`RotateDekAsync` generates a fresh DEK, wraps it via the KEK provider, then **atomically** swaps
it in as the scope's active key (`IEncryptionKeyStore.RotateAsync`: deactivate-old + insert-new
in one transaction). It does **not** re-encrypt existing payloads: every `EncryptedPayload`
carries its own wrapped DEK and remains decryptable forever — as long as Vault can still unwrap
that DEK version (see the `min_decryption_version` section below).

### Failure behaviour (0.2.0+): fail-safe

If the KEK provider or the store fails at any point during rotation, the operation throws and
**the previously-active key stays active** (and cached). The scope is never observed without an
active DEK, and encrypts keep working on the old key:

- Vault down during a `Vellum.Rotation` tick → the scope's attempt fails after
  `MaxRetriesPerScope` retries, is logged as an error, and is retried on the next tick. Encrypt
  and decrypt traffic continues on the cached/stored active key throughout.
- Vault down for regular traffic → encrypts keep working as long as the active DEK is in the
  in-memory cache (`VellumOptions.DekCacheTtl`); decrypts keep working for any DEK already in the
  wrapped-key cache. Cache misses fail closed until Vault returns.

## KEK rotation (Vault Transit)

The KEK never leaves Vault, so rotating it is a Vault operation, not a Vellum one:

```bash
vault write -f transit/keys/<key-name>/rotate
```

**This is safe by default.** Vault keeps every previous key version. After the rotation:

- New `WrapAsync` calls (new DEKs, i.e. the next DEK rotation or a brand-new scope) automatically
  wrap under the new KEK version — no Vellum configuration change, no restart.
- Every already-persisted wrapped DEK keeps unwrapping: the `vault:v<N>:...` ciphertext prefix
  tells Transit which key version to use, and Vellum round-trips the provider version verbatim
  (`WrappedKey.ProviderVersion`).

Inspect the key's version state at any time:

```bash
vault read transit/keys/<key-name>
```

```text
Key                       Value
---                       -----
latest_version            3
min_decryption_version    1
min_encryption_version    0
keys                      map[1:1712592000 2:1717862400 3:1726000000]
...
```

`latest_version` is what new wraps use; `min_decryption_version` is the oldest version Vault
will still unwrap. As long as `min_decryption_version` stays at (or below) the oldest version
referenced by any of your data, everything keeps working.

## The dangerous part: `min_decryption_version`

Vault lets you raise the minimum decryption version to retire old key material:

```bash
# DO NOT run this against a Vellum KEK — read this section first.
vault write transit/keys/<key-name>/config min_decryption_version=2
```

Once raised, Vault **refuses to unwrap** any ciphertext produced by an older version. For Vellum
this is uniquely destructive, because wrapped DEKs live in **two** places:

1. The key store (`EncryptionKey` rows) — the active and historical DEKs per scope.
2. **Inside every persisted `EncryptedPayload`** — each envelope embeds its own copy of the
   wrapped DEK (`WrappedDek`), which is what makes decryption self-contained.

If *any* persisted envelope (or stored key row) carries a wrapped DEK from a version below the
new `min_decryption_version`, that DEK can never be unwrapped again and those payloads are
**permanently undecryptable**. There is no recovery: not from backups of your database (the
envelopes in the backup carry the same dead wrapped DEKs), only from a Vault key-version
restore — if your Vault policy even retains the material.

### The safe procedure

1. **Rotate the Vault key** (`vault write -f transit/keys/<name>/rotate`). Safe, instant,
   reversible in effect — old versions keep working.
2. **Let new DEKs adopt the new version automatically.** Every DEK rotation from now on wraps
   under the new KEK version. With `Vellum.Rotation` at the default 24 h `MaxDekAge`, all
   *active* DEKs reference the new version within a day.
3. **Before ever bumping `min_decryption_version`**: every persisted envelope and every stored
   `EncryptionKey` row must first be rewrapped/re-encrypted so that nothing references a version
   below the new minimum. **Vellum has no rewrap tooling yet** (a rewrap utility leveraging
   Transit's `/rewrap` endpoint is planned). Until it exists, the operational rule is simple:

   > **Do not bump `min_decryption_version`. Ever.**

   The compensating control is that rotating the KEK (step 1) already addresses the realistic
   threat — newly-created material no longer depends on the old version — without destroying
   access to historical data.

### Pre-flight check (if you believe you must bump anyway)

Do not bump unless **all** of the following hold, verified, in order:

- [ ] You have inventoried the `vault:v<N>:` version prefix of `WrappedKey.Ciphertext` across
      **every** `EncryptionKey` row in the key store, for every scope, active *and* historical.
- [ ] You have inventoried the embedded `WrappedDek` version of **every persisted
      `EncryptedPayload`** in every table/blob/queue where envelopes are stored — including
      backups you may need to restore.
- [ ] The minimum version found across both inventories is **≥** the value you intend to set.
- [ ] You have a tested Vault disaster-recovery path for the key in question.

If you cannot complete the inventory (in practice: if envelopes are spread across systems you do
not fully control), you cannot bump safely. Leave `min_decryption_version` alone.

## Quick reference

| Operation | Command / API | Safe? |
|---|---|---|
| Rotate one scope's DEK | `IDekManager.RotateDekAsync(scope)` | Yes — atomic, fail-safe since 0.2.0 |
| Rotate all old DEKs continuously | `services.AddVellumRotation(...)` | Yes — age-gated, per-scope retry |
| Rotate the KEK | `vault write -f transit/keys/<name>/rotate` | Yes — old versions keep unwrapping |
| Inspect KEK versions | `vault read transit/keys/<name>` | Yes — read-only |
| Raise `min_decryption_version` | `vault write transit/keys/<name>/config min_decryption_version=N` | **No — permanently destroys access to any payload wrapped under version &lt; N. Do not run.** |
