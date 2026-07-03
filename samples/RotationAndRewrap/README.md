# Vellum — rotation and rewrap walkthrough (`Vellum.Static` + `Vellum.InMemory`)

> A narrated console tour of the 0.2.0 key-lifecycle features: manual DEK
> rotation, scope-bound (v2) envelopes, and the KEK rewrap tooling. No Vault,
> no database, no containers — runs to completion deterministically.

## Running

```bash
dotnet run --project samples/RotationAndRewrap
```

Expected output (GUIDs and ciphertexts vary per run):

```text
=== 1. Setup — AddVellum + Static KEK + InMemory store, two scopes ===
Scopes in play: "tenant:alpha" and "tenant:beta".

=== 2. Encrypt — each scope gets its own DEK, envelopes are v2 (scope-bound) ===
tenant:alpha KeyId: 0d63d6ab-...
FormatVersion:      2 (v2: the scope is baked into the AES-GCM associated data)
tenant:beta KeyId:  6e1ff051-... (different scope, different DEK)

=== 3. Manual rotation — IDekManager.RotateDekAsync("tenant:alpha") ===
KeyId before rotation: 0d63d6ab-...
KeyId after rotation:  9b6f7c3e-...
KeyId changed:         True
Pre-rotation envelope still decrypts: "alpha secret #1"

=== 4. Cross-scope binding — tenant:alpha's envelope presented as tenant:beta's ===
Rejected with AuthenticationTagMismatchException:
the AAD scope binding failed the AES-GCM authentication tag check (fail closed).

=== 5. KEK rewrap — refresh wrapped DEKs without touching payload bytes ===
Stored-key sweep:  Total=2, Rewrapped=2, Failed=0
WrappedDek before:    static:v1:0Nloze1gJcsqikLz7k... (90 chars)
WrappedDek after:     static:v1:07YuosLt2qYMF/UkLD... (90 chars)
WrappedDek changed:   True
Ciphertext identical: True
Nonce identical:      True
KeyId identical:      True
FormatVersion same:   True
Rewrapped envelope round-trips: "alpha secret #1"

=== 6. Opt-out — BindScopeToCiphertext = false produces legacy v1 envelopes ===
FormatVersion: 1 (v1: no AAD)
Decrypts under ANY scope argument — here "tenant:beta": "legacy-style envelope"
Only opt out when the scope genuinely cannot be supplied at decrypt time.

Done. Full KEK-rotation procedure: docs/kek-rotation.md
```

## What this sample demonstrates

- **Manual DEK rotation** — `IDekManager.RotateDekAsync(scope)` atomically swaps
  in a fresh DEK (fail-safe since 0.2.0: if the KEK provider or the store fails,
  the old key stays active). New encrypts pick up the new `KeyId`; envelopes
  produced before the rotation keep decrypting via their embedded wrapped DEK.
- **Scope binding (format version 2)** — the scope is bound into the AES-GCM
  associated data, so an envelope encrypted for `tenant:alpha` presented as
  `tenant:beta`'s data fails the authentication tag check instead of decrypting
  (confused-deputy / envelope-swap defense).
- **KEK rewrap tooling** — `VellumRewrapService.RewrapStoredKeysAsync(scope)`
  refreshes the key-store rows (step 2 of the
  [KEK rotation runbook](../../docs/kek-rotation.md)) and
  `IPayloadEncryptor.RewrapPayloadAsync(envelope)` refreshes the wrapped DEK
  embedded in each persisted envelope (step 3). Only the wrapped DEK changes —
  ciphertext, nonce, key id and format version are carried over verbatim, and
  both operations are idempotent.
- **The v1 opt-out** — `VellumOptions.BindScopeToCiphertext = false` produces
  legacy unbound envelopes that decrypt under any scope argument. The trade-off
  is explicit and should be rare.

Note on the dev provider: with `Vellum.Static`, rewrap is an in-process
unwrap + wrap. With `Vellum.Vault` it delegates to Transit's native `/rewrap`
endpoint, so plaintext DEKs never leave Vault.

This sample deliberately does **not** reference `Vellum.Rotation` — it shows the
manual flow. For the background worker (`AddVellumRotation`), see
[`samples/AspNetCore.Postgres.Vault`](../AspNetCore.Postgres.Vault).

## What to read next

- [`docs/kek-rotation.md`](../../docs/kek-rotation.md) — the full runbook,
  including the one Vault knob that can permanently destroy data
  (`min_decryption_version`) and why the rewrap sweep must come first.
- [`samples/AspNetCore.Postgres.Vault`](../AspNetCore.Postgres.Vault) —
  background rotation via `Vellum.Rotation` plus the rewrap runbook steps as
  HTTP admin endpoints, against real Vault + Postgres.
- [`samples/Console.Static`](../Console.Static) — the minimal Hello World, and
  the warnings about `Vellum.Static` (dev only!) that apply here too.
