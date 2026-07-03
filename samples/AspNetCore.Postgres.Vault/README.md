# Vellum — ASP.NET Core + PostgreSQL + Vault sample

> A minimal web app that encrypts "secret notes" via AES-GCM, wraps the DEK
> through HashiCorp Vault Transit, and persists the wrapped DEK in PostgreSQL
> through `Vellum.EntityFrameworkCore`. Uses the single-source
> options flow (`UseVellum` + `AddEntityFrameworkCoreStore<T>`, no literal
> duplication).

## Stack

- **AES-GCM** via `Vellum.Core` (DEK encrypt/decrypt)
- **Vault Transit** as the KEK provider via `Vellum.Vault`
- **PostgreSQL** as the store via `Vellum.EntityFrameworkCore` + `Npgsql.EntityFrameworkCore.PostgreSQL`
- **Background DEK rotation** via `Vellum.Rotation` (sample-friendly timings)
- **.NET 10** minimal API

## Run locally

### 1. Start Vault + Postgres containers

```bash
cd samples/AspNetCore.Postgres.Vault
docker compose up -d
```

Wait for both containers to become healthy (`docker compose ps` should show
`healthy` for each).

### 2. Enable Vault Transit and create the KEK

```bash
# Enable the transit secrets engine
curl -sf -X POST \
    -H "X-Vault-Token: dev-root" \
    http://localhost:8200/v1/sys/mounts/transit \
    -d '{"type":"transit"}'

# Create the KEK that Vellum will use
curl -sf -X POST \
    -H "X-Vault-Token: dev-root" \
    http://localhost:8200/v1/transit/keys/vellum-sample-kek \
    -d '{}'
```

### 3. Run the app

```bash
dotnet run --project samples/AspNetCore.Postgres.Vault
```

The app ensures the schema exists via `EnsureCreatedAsync` (so you can poke at it
without running `dotnet ef migrations add` first).

### 4. Exercise the endpoints

```bash
# Create an encrypted note
curl -X POST http://localhost:5000/notes \
    -H 'Content-Type: application/json' \
    -d '{"text":"hello vellum"}'
# => {"id":"<guid>"}

# Fetch and decrypt it
curl http://localhost:5000/notes/<guid>
# => {"id":"<guid>","text":"hello vellum"}
```

The second fetch for the same note is fully cache-hot — the wrapped-DEK is served
from Vellum's built-in decrypt cache (see
[#6](https://github.com/OkaySire/vellum/issues/6)). No round-trip to Vault on the
second read.

## Watch a rotation happen

The sample registers `Vellum.Rotation` with timings tuned for impatient humans
(production defaults are 24 h interval / 24 h max DEK age — see the comment in
`Program.cs`):

| Option | Sample value | Production default |
|---|---|---|
| `StartupDelay` | 10 s | 1 min |
| `RotationInterval` | 1 min | 24 h |
| `MaxDekAge` | 2 min | 24 h |

To see it live:

1. `dotnet run --project samples/AspNetCore.Postgres.Vault` and POST a note —
   this creates the first DEK for `sample:global`.
2. Wait. The worker ticks ~10 s after start, then every minute. The first tick
   that finds the active DEK **older than 2 minutes** rotates it — so roughly
   2–3 minutes after the first POST you'll see the rotation in the logs
   (`Rotated DEK for scope sample:global`).
3. POST another note and compare the `vellum_encryption_keys` table: the new
   note's `KeyId` references the new active key, the old key row is now
   `IsActive = false`, and the old note still decrypts (its envelope embeds its
   own wrapped DEK).

```sql
-- psql -h localhost -U postgres vellum_sample
SELECT "KeyId", "IsActive", "CreatedAt" FROM vellum_encryption_keys ORDER BY "CreatedAt";
```

## KEK rotation: the rewrap endpoints

After rotating the **KEK** in Vault (`vault write -f transit/keys/vellum-sample-kek/rotate`),
the [KEK rotation runbook](../../docs/kek-rotation.md) requires rewrapping all stored
wrapped DEKs before old KEK versions can ever be retired. This sample ships both
runbook steps as admin endpoints (in production they would sit behind authorization;
the sample has no auth stack at all):

```bash
# Step 2 of the runbook — rewrap the scope's stored keys (active + historical).
# Idempotent; re-run until "failed" is 0.
curl -X POST http://localhost:5000/admin/rewrap/sample:global
# => {"total":2,"rewrapped":2,"failed":0,"failedKeyIds":[]}

# Step 3 of the runbook — every persisted envelope embeds its own copy of the
# wrapped DEK, so each secret_notes row needs RewrapPayloadAsync too.
curl -X POST http://localhost:5000/admin/rewrap-notes/sample:global
# => {"scope":"sample:global","rewrappedNotes":3}
```

Only the wrapped DEK changes in each row — ciphertext, nonce, key id and format
version are untouched, and the plaintext DEKs never leave Vault (Transit's native
`/rewrap`). Do **not** raise `min_decryption_version` before both sweeps report
zero failures — read the runbook first.

## Production auth: AppRole

The dev token (`dev-root`) is fine for `vault server -dev`, but a fixed token in
production expires into a silent outage. `Vellum.Vault` supports AppRole: tokens
are acquired at startup and re-acquired automatically at 80 % of their lease
(`VaultOptions.TokenRenewalThreshold`).

Create the AppRole in Vault (using the dev containers:
`docker compose exec vault sh`, then `export VAULT_ADDR=http://127.0.0.1:8200
VAULT_TOKEN=dev-root`):

```bash
# 1. Enable the AppRole auth method
vault auth enable approle

# 2. A policy limited to what Vellum actually needs on the KEK
vault policy write vellum-sample - <<'EOF'
path "transit/encrypt/vellum-sample-kek" { capabilities = ["update"] }
path "transit/decrypt/vellum-sample-kek" { capabilities = ["update"] }
path "transit/rewrap/vellum-sample-kek"  { capabilities = ["update"] }
EOF

# 3. The role with that policy and short-lived tokens
vault write auth/approle/role/vellum-sample \
    token_policies=vellum-sample \
    token_ttl=1h \
    token_max_ttl=4h

# 4. Read the role id (not secret) and mint a secret id (secret!)
vault read auth/approle/role/vellum-sample/role-id
vault write -f auth/approle/role/vellum-sample/secret-id
```

Then switch the sample over via configuration. The credentials are deliberately
**not** stubbed in `appsettings.json`: `SecretId` is a secret, and a committed
placeholder invites copy-pasting real credentials into the repository. Use
environment variables (or a secret store) instead — the `Vault__*` double
underscore maps to the `Vault:` section:

```bash
export Vault__AuthMethod=AppRole
export Vault__RoleId=<role_id from step 4>
export Vault__SecretId=<secret_id from step 4>
dotnet run --project samples/AspNetCore.Postgres.Vault
```

`Program.cs` leaves `Token` empty in AppRole mode — `VaultOptions` validation
rejects mixed configurations at startup (fail fast).

## What to look at in the code

- `Program.cs` — DI wiring. Note the `UseVellum` call on the
  `DbContextOptionsBuilder`, and the single `AddEntityFrameworkCoreStore<AppDbContext>()`
  call with no configure delegate — all options already flowed in via `UseVellum`.
  Also: the Token/AppRole switch in `AddVaultProvider`, the `AddVellumRotation`
  registration with its sample-vs-production timing comment, and the two
  `/admin/rewrap*` endpoints implementing the runbook's per-scope sweeps.
- `AppDbContext.cs` — `OnModelCreating` calls `modelBuilder.AddVellumEncryptionKeys(this)`.
  The `this` parameter is what lets Vellum read the options back from the same
  `DbContextOptionsBuilder` pipeline.
- `SecretNote.cs` — a plain entity holding the `EncryptedPayload` fields unpacked
  into columns. Production code might prefer a single `jsonb` column; this form is
  easier to debug in a SQL shell.

## Cleaning up

```bash
cd samples/AspNetCore.Postgres.Vault
docker compose down --volumes
```

## Also see

- [`samples/Console.Static`](../Console.Static) — zero-dependency quickstart
- [`samples/RotationAndRewrap`](../RotationAndRewrap) — the manual rotation +
  rewrap flow as a deterministic console walkthrough (no infrastructure)
- [`docs/kek-rotation.md`](../../docs/kek-rotation.md) — the full KEK rotation
  runbook the `/admin/rewrap*` endpoints implement
- [`samples/MigrationFromCustom`](../MigrationFromCustom) — migrating an existing
  custom encryption layer to this stack without data loss
- [`samples/FeatureFlagged`](../FeatureFlagged) — feature-flag decorator for staged
  rollouts
- [`docs/consumer-options-bridging.md`](../../docs/consumer-options-bridging.md) —
  how to flow `appsettings.json` values into Vellum's `Action<TOptions>` delegates
