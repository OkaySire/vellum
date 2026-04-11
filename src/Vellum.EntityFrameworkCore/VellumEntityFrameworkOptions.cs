namespace Vellum.EntityFrameworkCore;

/// <summary>
/// Configuration for the Entity Framework Core-backed <see cref="IEncryptionKeyStore"/>.
/// </summary>
/// <remarks>
/// <para>
/// These options configure the storage layout (table name, schema, column names, column
/// length) and the SQL fragment used by the filtered unique index that enforces the
/// "one active key per scope" invariant.
/// </para>
/// <para>
/// <b>Where to configure.</b> Call <c>UseVellum</c> on the same <c>DbContextOptionsBuilder</c>
/// you pass to <c>AddDbContext&lt;T&gt;</c>, and/or pass a configure delegate to
/// <c>AddEntityFrameworkCoreStore&lt;T&gt;</c>. Inside <c>DbContext.OnModelCreating</c>, call
/// <c>modelBuilder.AddVellumEncryptionKeys(this)</c>; the extension reads the options back
/// from the context (first via <c>UseVellum</c>, then via <c>IOptions&lt;VellumEntityFrameworkOptions&gt;</c>
/// on the application service provider) so the consumer never has to pass them twice.
/// </para>
/// <para>
/// <b>Filtered unique index portability.</b> The core contract of this package is that
/// at most one <see cref="EncryptionKey"/> per <see cref="EncryptionKey.Scope"/> is
/// active at any time. This is enforced at the database level with a filtered unique
/// index over <c>Scope</c> where <c>IsActive</c> is true. Every provider spells the
/// filter clause differently, so <see cref="UniqueActiveIndexFilter"/> must match the
/// provider that the consumer's <c>DbContext</c> is wired to:
/// </para>
/// <list type="bullet">
///   <item><description><b>SQL Server</b>: <c>[IsActive] = 1</c> (default)</description></item>
///   <item><description><b>PostgreSQL (Npgsql)</b>: <c>"IsActive" = true</c></description></item>
///   <item><description><b>SQLite</b>: <c>"IsActive" = 1</c></description></item>
///   <item><description><b>MySQL (Pomelo)</b>: filtered indexes are not supported — configure a non-filtered composite unique index or enforce uniqueness in application code</description></item>
/// </list>
/// <para>
/// The default targets SQL Server because it is the most common .NET corporate stack.
/// Consumers running any other provider <b>must</b> override
/// <see cref="UniqueActiveIndexFilter"/> in their registration call.
/// </para>
/// <para>
/// <b>Column name overrides (issue #8).</b> Consumers integrating with an existing
/// snake_case schema can rename every column via the dedicated
/// <c>*ColumnName</c> properties. When a column is renamed, the consumer is also
/// responsible for keeping <see cref="UniqueActiveIndexFilter"/> in sync — the filter is
/// a raw SQL fragment that references the <c>IsActive</c> column by name, so renaming
/// <see cref="IsActiveColumnName"/> typically requires updating the filter to match.
/// </para>
/// </remarks>
public sealed class VellumEntityFrameworkOptions
{
    /// <summary>
    /// Gets or sets the table name used for the wrapped Data Encryption Key storage.
    /// Defaults to <c>vellum_encryption_keys</c>.
    /// </summary>
    public string TableName { get; set; } = "vellum_encryption_keys";

    /// <summary>
    /// Gets or sets the optional schema name for the encryption key table. When
    /// <see langword="null"/>, the provider-default schema is used (for example <c>dbo</c>
    /// on SQL Server or <c>public</c> on PostgreSQL).
    /// </summary>
    public string? SchemaName { get; set; }

    /// <summary>
    /// Gets or sets the SQL fragment used as the filter of the "only one active key per
    /// scope" unique index. Defaults to <c>[IsActive] = 1</c> (SQL Server syntax).
    /// </summary>
    /// <remarks>
    /// See the type-level remarks on <see cref="VellumEntityFrameworkOptions"/> for the
    /// per-provider syntax. If you rename <see cref="IsActiveColumnName"/>, update this
    /// filter to reference the new column name.
    /// </remarks>
    public string UniqueActiveIndexFilter { get; set; } = "[IsActive] = 1";

    /// <summary>
    /// Gets or sets the maximum length of the <see cref="EncryptionKey.Scope"/> column.
    /// Defaults to 256 characters, which is long enough for typical tenant identifiers
    /// and short enough to index efficiently on every major provider.
    /// </summary>
    public int ScopeMaxLength { get; set; } = 256;

    /// <summary>
    /// Gets or sets the maximum length of the <see cref="WrappedKey.ProviderVersion"/>
    /// column. Defaults to 512 characters, which comfortably holds AWS KMS key ARNs,
    /// Azure Key Vault key identifiers, and GCP KMS resource paths.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Raise this only if you use a KEK provider whose version identifier is longer than
    /// 512 characters (unusual but not impossible for deeply-nested GCP KMS resource paths).
    /// Lower it only if you have a strict column-length budget and know your provider emits
    /// short identifiers — shortening the column on an existing table requires a manual
    /// data migration.
    /// </para>
    /// </remarks>
    public int WrappedProviderVersionMaxLength { get; set; } = 512;

    /// <summary>
    /// Gets or sets the column name for the DEK identifier. Defaults to <c>KeyId</c>.
    /// Override to match an existing snake_case schema (e.g. <c>key_id</c>).
    /// </summary>
    public string KeyIdColumnName { get; set; } = "KeyId";

    /// <summary>
    /// Gets or sets the column name for the opaque scope identifier. Defaults to <c>Scope</c>.
    /// Override to match an existing snake_case schema (e.g. <c>scope</c>).
    /// </summary>
    public string ScopeColumnName { get; set; } = "Scope";

    /// <summary>
    /// Gets or sets the column name for the wrapped DEK ciphertext. Defaults to
    /// <c>WrappedCiphertext</c>. Override to match an existing snake_case schema
    /// (e.g. <c>wrapped_ciphertext</c>).
    /// </summary>
    public string WrappedCiphertextColumnName { get; set; } = "WrappedCiphertext";

    /// <summary>
    /// Gets or sets the column name for the KEK provider version. Defaults to
    /// <c>WrappedProviderVersion</c>. Override to match an existing snake_case schema
    /// (e.g. <c>wrapped_provider_version</c>).
    /// </summary>
    public string WrappedProviderVersionColumnName { get; set; } = "WrappedProviderVersion";

    /// <summary>
    /// Gets or sets the column name for the creation timestamp. Defaults to <c>CreatedAt</c>.
    /// Override to match an existing snake_case schema (e.g. <c>created_at</c>).
    /// </summary>
    public string CreatedAtColumnName { get; set; } = "CreatedAt";

    /// <summary>
    /// Gets or sets the column name for the optional expiry timestamp. Defaults to
    /// <c>ExpiresAt</c>. Override to match an existing snake_case schema
    /// (e.g. <c>expires_at</c>).
    /// </summary>
    public string ExpiresAtColumnName { get; set; } = "ExpiresAt";

    /// <summary>
    /// Gets or sets the column name for the active flag. Defaults to <c>IsActive</c>.
    /// </summary>
    /// <remarks>
    /// When renaming this column, update <see cref="UniqueActiveIndexFilter"/> in lockstep
    /// so the filtered unique index references the new column name. For example, renaming
    /// <see cref="IsActiveColumnName"/> to <c>is_active</c> on PostgreSQL requires changing
    /// <see cref="UniqueActiveIndexFilter"/> to <c>"is_active" = true</c>.
    /// </remarks>
    public string IsActiveColumnName { get; set; } = "IsActive";
}
