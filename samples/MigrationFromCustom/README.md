# Vellum — Migration from a custom encryption layer

> **Applies to**: consumers who already have encrypted data in production, wrapped
> and stored with a hand-rolled layer, and now want to adopt Vellum without losing
> historical ciphertexts or re-encrypting live data.

## What this sample is

A **recipe**, not a runnable project. The tricky part of migrating an existing
encryption layer to Vellum is the SQL data migration — renaming columns,
back-filling the opaque `Scope`, mapping a legacy integer KEK version to
`WrappedProviderVersion`, and generating an EF Core migration that the scaffolder
can't produce automatically. This sample walks through the exact steps taken
during the `jacqcloud-buses` v0.1.63 → Vellum 0.1.0-preview.1 migration (see the
feedback report's section 6 for the full timeline — ~1h50 end-to-end).

## Starting schema (legacy)

`bus_encryption_keys` was the consumer's custom table:

```sql
CREATE TABLE runtime.bus_encryption_keys (
    id                 UUID        PRIMARY KEY,
    bus_instance_id    UUID        NOT NULL,      -- tenant identifier
    organization_id    UUID        NOT NULL,      -- the "other" tenant identifier
    encrypted_dek      VARCHAR(2048) NOT NULL,    -- the wrapped DEK ciphertext
    vault_key_version  INT         NOT NULL,      -- Vault Transit integer version
    created_at         TIMESTAMPTZ NOT NULL,
    expires_at         TIMESTAMPTZ,
    is_active          BOOLEAN     NOT NULL
);
CREATE UNIQUE INDEX ux_bus_enc_keys_one_active
    ON runtime.bus_encryption_keys (bus_instance_id)
    WHERE is_active = true;
```

## Target schema (Vellum)

Vellum's `EncryptionKeyRecord` (renamed at will via the column-name overrides
added in [#8](https://github.com/OkaySire/vellum/issues/8)) is:

| Column                    | Type              | Notes                              |
|---------------------------|-------------------|------------------------------------|
| `KeyId`                   | `UUID`            | primary key                        |
| `Scope`                   | `VARCHAR(256)`    | opaque tenant identifier           |
| `WrappedCiphertext`       | `TEXT`            | wrapped DEK ciphertext             |
| `WrappedProviderVersion`  | `VARCHAR(512)`    | KEK provider version (string)      |
| `CreatedAt`               | `TIMESTAMPTZ`     |                                    |
| `ExpiresAt`               | `TIMESTAMPTZ`     |                                    |
| `IsActive`                | `BOOLEAN`         |                                    |

Note — since 0.1.0-preview.2, consumers can rename each column via
`VellumEntityFrameworkOptions` (e.g. to stay snake_case). This sample uses the
PascalCase defaults for clarity; see
[`samples/AspNetCore.Postgres.Vault`](../AspNetCore.Postgres.Vault) for a snake_case
variant.

## Migration recipe

### 1. Generate a baseline migration with `dotnet ef migrations add`

```bash
dotnet ef migrations add MigrateToVellumEncryptionKeys \
    --context AppDbContext \
    --output-dir Infrastructure/Migrations
```

**The scaffolder's `Up()` will be wrong.** Its rename heuristic may decide that
`organization_id` should be renamed to `KeyId` (a semantic disaster — the column
holds a tenant id, not the DEK identity). You have to rewrite `Up()` by hand.

### 2. Replace `Up()` with the content below

`Migrations/20260410120000_MigrateToVellumEncryptionKeys.cs`:

```csharp
using Microsoft.EntityFrameworkCore.Migrations;

public partial class MigrateToVellumEncryptionKeys : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // 1. Drop the legacy filtered unique index — we'll recreate it on Scope below.
        migrationBuilder.DropIndex(
            name: "ux_bus_enc_keys_one_active",
            schema: "runtime",
            table: "bus_encryption_keys");

        // 2. Drop organization_id — Vellum has no tenant concept at this layer.
        //    Any multi-tenant affinity must live inside the Scope string.
        migrationBuilder.DropColumn(
            name: "organization_id",
            schema: "runtime",
            table: "bus_encryption_keys");

        // 3. Rename the PK column: id -> KeyId (preserves the DEK Guids).
        migrationBuilder.RenameColumn(
            name: "id",
            schema: "runtime",
            table: "bus_encryption_keys",
            newName: "KeyId");

        // 4. Add the Scope column and back-fill it from bus_instance_id.
        migrationBuilder.AddColumn<string>(
            name: "Scope",
            schema: "runtime",
            table: "bus_encryption_keys",
            type: "character varying(256)",
            maxLength: 256,
            nullable: false,
            defaultValue: string.Empty);

        migrationBuilder.Sql(
            """
            UPDATE runtime.bus_encryption_keys
               SET "Scope" = 'bus:' || bus_instance_id::text;
            """);

        // 5. Add WrappedProviderVersion and back-fill from vault_key_version.
        //    ⚠️ CRITICAL FORMAT: Vellum's VaultKeyEncryptionProvider emits 'v<N>'
        //    (with the 'v' prefix), so the back-fill MUST match that format or
        //    audit tools + new Vellum-native rows will disagree silently.
        //    Backend's dogfood integration suite caught this — see
        //    feedback-report.md section 10.3.
        migrationBuilder.AddColumn<string>(
            name: "WrappedProviderVersion",
            schema: "runtime",
            table: "bus_encryption_keys",
            type: "character varying(512)",
            maxLength: 512,
            nullable: false,
            defaultValue: string.Empty);

        migrationBuilder.Sql(
            """
            UPDATE runtime.bus_encryption_keys
               SET "WrappedProviderVersion" = 'v' || vault_key_version::text;
            """);

        // 6. Drop legacy columns now that every row has Scope + WrappedProviderVersion.
        migrationBuilder.DropColumn(
            name: "bus_instance_id",
            schema: "runtime",
            table: "bus_encryption_keys");
        migrationBuilder.DropColumn(
            name: "vault_key_version",
            schema: "runtime",
            table: "bus_encryption_keys");

        // 7. Rename the remaining columns to the PascalCase defaults. If you are using
        //    the 0.1.0-preview.2 column-name overrides to stay snake_case, SKIP this step
        //    and configure VellumEntityFrameworkOptions.{Xxx}ColumnName instead.
        migrationBuilder.RenameColumn("encrypted_dek", "runtime", "bus_encryption_keys", "WrappedCiphertext");
        migrationBuilder.RenameColumn("created_at",    "runtime", "bus_encryption_keys", "CreatedAt");
        migrationBuilder.RenameColumn("expires_at",    "runtime", "bus_encryption_keys", "ExpiresAt");
        migrationBuilder.RenameColumn("is_active",     "runtime", "bus_encryption_keys", "IsActive");

        // 8. Recreate the filtered unique index on Scope where IsActive.
        migrationBuilder.CreateIndex(
            name: "IX_vellum_encryption_keys_Scope_Active",
            schema: "runtime",
            table: "bus_encryption_keys",
            column: "Scope",
            unique: true,
            filter: "\"IsActive\" = true");

        // 9. Non-unique index on Scope for historical lookups.
        migrationBuilder.CreateIndex(
            name: "IX_bus_encryption_keys_Scope",
            schema: "runtime",
            table: "bus_encryption_keys",
            column: "Scope");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        // Symmetric rollback. If you ship this migration, write Down() — rolling
        // forward in prod without a tested Down() is how data disasters happen.
        // See feedback-report.md section 10.3 for the 'v<N>' → 'N' reverse transform.
        throw new NotImplementedException("Write a symmetric Down() before shipping.");
    }
}
```

### 3. Validate the migration BEFORE shipping it

This is where the jacqcloud-buses team saved themselves from a silent data-format
drift incident. Write an integration test that:

1. Creates a database, applies the legacy baseline migration, and seeds a handful of
   scenario rows (single active DEK, multiple historical DEKs, zero DEKs, `v12`
   vault version, two buses under one organization).
2. Applies `MigrateToVellumEncryptionKeys` on top.
3. Asserts:
   - Row count (use `WHERE KeyId = ANY(@seededIds)` — scoped to the test's own rows,
     so sibling fixtures don't pollute the count).
   - `Scope = 'bus:<guid>'` for each seeded row.
   - `WrappedProviderVersion ~ '^v[0-9]+$'` — this is the assertion that caught the
     `'1'` vs `'v1'` bug.
   - `KeyId` values are preserved (not regenerated).
   - Exactly one active row per scope.
   - Legacy columns (`organization_id`, `bus_instance_id`, `vault_key_version`,
     `encrypted_dek`) are gone.
4. Round-trips a pre-migration encrypted payload through the new Vellum stack —
   `IPayloadEncryptor.DecryptAsync` must still succeed against the migrated rows,
   proving the `KeyId` preservation and `WrappedCiphertext` rename did not corrupt
   the envelopes.
5. Round-trips a brand-new Vellum-native encrypt → store → decrypt through the same
   `DbContext` to prove the post-migration write path works.

Run this in CI **before** merging the migration PR. A path-filtered GitHub Actions
workflow that only fires when encryption-related files change keeps unrelated PRs
off the integration track. See the `jacqcloud-buses` feedback report's section 10.1
for the full test architecture (15 assertions, 5 seed scenarios, 1h50 to build).

## Gotchas the jacqcloud-buses team hit

1. **`WrappedProviderVersion = '1'` vs `'v1'`**: Vellum's `VaultKeyEncryptionProvider`
   emits `'v<N>'`. A back-fill that drops the `v` prefix looks fine on a SELECT
   (round-trips through Vault either way), but audit tools and new Vellum-native
   rows will format-disagree. Integration assertion: `~ '^v[0-9]+$'`.
2. **`organization_id` is a tenant identifier, not the DEK identity.** Do not let
   the EF scaffolder rename it to `KeyId`. Drop it, fold its content into `Scope` via
   the back-fill, done.
3. **Shared test collection row count**: `COUNT(*)` assertions over a shared test
   fixture are flaky when sibling tests create fresh DEKs during their run. Always
   scope the count to the rows the migration test itself seeded
   (`WHERE KeyId = ANY(@seededIds)`).
4. **`bus_encryption_keys` name change**: if your legacy table is `bus_encryption_keys`
   and you want Vellum to pick up the same table, set
   `VellumEntityFrameworkOptions.TableName = "bus_encryption_keys"` in
   `AddEntityFrameworkCoreStore<T>()`. Vellum's default is `vellum_encryption_keys`.

## Relation to other samples

- [`samples/AspNetCore.Postgres.Vault`](../AspNetCore.Postgres.Vault) shows the
  **target** runtime configuration this migration is moving the consumer toward.
- [`samples/FeatureFlagged`](../FeatureFlagged) shows how to guard the rollout of the
  new Vellum stack behind a feature flag during staged deployment.
