namespace Vellum.EntityFrameworkCore;

/// <summary>
/// Configuration for the Entity Framework Core-backed <see cref="IEncryptionKeyStore"/>.
/// </summary>
/// <remarks>
/// <para>
/// These options configure the storage layout (table name, schema, column length) and the
/// SQL fragment used by the filtered unique index that enforces the "one active key per
/// scope" invariant. They must be set before the consumer's <c>DbContext.OnModelCreating</c>
/// calls <c>VellumModelBuilderExtensions.AddVellumEncryptionKeys</c>.
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
    /// per-provider syntax.
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
}
