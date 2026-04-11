# Vellum — minimal console sample (`Vellum.Static` + `Vellum.InMemory`)

> Twenty-line Hello World for Vellum. No Vault, no database, no containers.
> Encrypts a string, decrypts it, prints both.

## Running

```bash
dotnet run --project samples/Console.Static
```

Expected output:

```text
KeyId:            e4a1b72c-...
Ciphertext bytes: 40 (plaintext + 16-byte auth tag)
Nonce bytes:      12
Wrapped provider: v1

Decrypted:        "hello from Vellum.Static"
```

## What this sample is (and is NOT) for

- ✅ Proving your local environment can build and run Vellum.
- ✅ Poking at `EncryptedPayload` / `WrappedKey` / `IPayloadEncryptor` interactively
  in the debugger.
- ✅ Unit tests that need a real crypto path without any infrastructure.
- ❌ **Any production use.** `Vellum.Static` holds the Key Encryption Key in process
  memory, bootstrapped from configuration. A process dump, memory-read primitive, or
  environment-variable leak compromises every wrapped DEK. Always use `Vellum.Vault`,
  `Vellum.AzureKeyVault`, `Vellum.AwsKms`, or `Vellum.GcpKms` in production.

## What to read next

- [`samples/AspNetCore.Postgres.Vault`](../AspNetCore.Postgres.Vault) — a realistic
  web-app stack with Vault Transit + Npgsql + migrations.
- [`samples/MigrationFromCustom`](../MigrationFromCustom) — how to port an existing
  custom encryption layer to Vellum without losing historical ciphertexts.
- [`samples/FeatureFlagged`](../FeatureFlagged) — staged rollouts via a feature-flag
  decorator over `IPayloadEncryptor`.
