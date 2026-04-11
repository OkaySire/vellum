# Vellum — ASP.NET Core + PostgreSQL + Vault sample

> A minimal web app that encrypts "secret notes" via AES-GCM, wraps the DEK
> through HashiCorp Vault Transit, and persists the wrapped DEK in PostgreSQL
> through `Vellum.EntityFrameworkCore`. Uses the new 0.1.0-preview.2 single-source
> options flow (`UseVellum` + `AddEntityFrameworkCoreStore<T>`, no literal
> duplication).

## Stack

- **AES-GCM** via `Vellum.Core` (DEK encrypt/decrypt)
- **Vault Transit** as the KEK provider via `Vellum.Vault`
- **PostgreSQL** as the store via `Vellum.EntityFrameworkCore` + `Npgsql.EntityFrameworkCore.PostgreSQL`
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

## What to look at in the code

- `Program.cs` — DI wiring. Note the `UseVellum` call on the
  `DbContextOptionsBuilder`, and the single `AddEntityFrameworkCoreStore<AppDbContext>()`
  call with no configure delegate — all options already flowed in via `UseVellum`.
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
- [`samples/MigrationFromCustom`](../MigrationFromCustom) — migrating an existing
  custom encryption layer to this stack without data loss
- [`samples/FeatureFlagged`](../FeatureFlagged) — feature-flag decorator for staged
  rollouts
- [`docs/consumer-options-bridging.md`](../../docs/consumer-options-bridging.md) —
  how to flow `appsettings.json` values into Vellum's `Action<TOptions>` delegates
