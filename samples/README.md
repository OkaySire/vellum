# Vellum samples

Runnable reference implementations for the patterns surfaced by the
jacqcloud-buses Phase 2 dogfood. All samples target .NET 10 and reference the
in-tree Vellum projects via `<ProjectReference>`, so you can clone the repo
and run them against local HEAD without installing anything from NuGet.

| Folder | Purpose |
|---|---|
| [`Console.Static`](Console.Static) | Twenty-line Hello World. `Vellum.Static` KEK + `Vellum.InMemory` store. No external dependencies. |
| [`AspNetCore.Postgres.Vault`](AspNetCore.Postgres.Vault) | Full web-app stack: ASP.NET Core minimal API + Npgsql + HashiCorp Vault Transit. Ships a `docker-compose.yml` for local Vault + Postgres containers. |
| [`FeatureFlagged`](FeatureFlagged) | `IPayloadEncryptor` decorator gated on `IOptionsMonitor<FeatureFlags>` for staged rollouts. Sentinel-passthrough pattern documented in the README. |
| [`MigrationFromCustom`](MigrationFromCustom) | Recipe (not a runnable project) for migrating an existing custom encryption layer to Vellum, with the exact EF Core migration used by `jacqcloud-buses` v0.1.63 → Vellum 0.1.0-preview.1. Includes the gotchas the migration suite caught (e.g. `'v<N>'` vs `'<N>'`). |
| [`CachingDecrypt`](CachingDecrypt) | **Tombstone.** Documents why this pattern became obsolete in 0.1.0-preview.2 after [#6](https://github.com/OkaySire/vellum/issues/6) baked the decrypt cache directly into `Vellum.Core`. |

## Running a sample

```bash
dotnet run --project samples/Console.Static
dotnet run --project samples/FeatureFlagged
# The ASP.NET Core sample needs Vault + Postgres containers — see its README.
docker compose -f samples/AspNetCore.Postgres.Vault/docker-compose.yml up -d
dotnet run --project samples/AspNetCore.Postgres.Vault
```

## Also see

- [`docs/consumer-options-bridging.md`](../docs/consumer-options-bridging.md) — how
  to flow `appsettings.json`-bound consumer options into Vellum's
  `Action<TOptions>` delegates without resorting to
  `services.BuildServiceProvider()` inside a delegate.
- [`CHANGELOG.md`](../CHANGELOG.md) — the release notes that link each sample
  back to the issue that motivated it.
