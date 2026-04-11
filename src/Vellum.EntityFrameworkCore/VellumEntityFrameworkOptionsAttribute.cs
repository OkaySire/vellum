namespace Vellum.EntityFrameworkCore;

/// <summary>
/// Declarative, per-<see cref="Microsoft.EntityFrameworkCore.DbContext"/> source of
/// <see cref="VellumEntityFrameworkOptions"/> that is readable at both runtime and design
/// time. Apply this attribute on a <see cref="Microsoft.EntityFrameworkCore.DbContext"/>
/// class to make the Vellum column-name overrides, table name, index filter, and length
/// limits part of the type itself — which means they survive the design-time scaffolder
/// even when the consumer ships an
/// <see cref="Microsoft.EntityFrameworkCore.Design.IDesignTimeDbContextFactory{TContext}"/>
/// that does not call
/// <see cref="VellumDbContextOptionsBuilderExtensions.UseVellum(Microsoft.EntityFrameworkCore.DbContextOptionsBuilder, System.Action{VellumEntityFrameworkOptions}?)"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Issue #17.</b> <c>dotnet ef migrations add</c> prefers
/// <see cref="Microsoft.EntityFrameworkCore.Design.IDesignTimeDbContextFactory{TContext}"/>
/// over building the host when both are available. A factory that only calls
/// <c>UseNpgsql(...)</c> (or any other provider extension) and forgets <c>UseVellum</c>
/// produces <see cref="Microsoft.EntityFrameworkCore.DbContextOptions"/> without the
/// Vellum options extension, and the scaffolder generates a migration against Vellum's
/// defaults (PascalCase column names, SQL Server filter syntax) instead of the consumer's
/// configured schema. Decorating the <see cref="Microsoft.EntityFrameworkCore.DbContext"/>
/// class with <see cref="VellumEntityFrameworkOptionsAttribute"/> gives the
/// <c>AddVellumEncryptionKeys</c> model builder extension a fallback source of options
/// that does not depend on the options-builder pipeline, so the runtime model and the
/// scaffolded migration stay in sync without forcing the consumer to duplicate a
/// <c>UseVellum</c> call inside their design-time factory.
/// </para>
/// <para>
/// <b>Resolution order.</b> <c>AddVellumEncryptionKeys</c> picks the first source that
/// exists:
/// </para>
/// <list type="number">
///   <item><description>
///     Options attached via
///     <see cref="VellumDbContextOptionsBuilderExtensions.UseVellum(Microsoft.EntityFrameworkCore.DbContextOptionsBuilder, System.Action{VellumEntityFrameworkOptions}?)"/>
///     on the <see cref="Microsoft.EntityFrameworkCore.DbContextOptionsBuilder"/> (highest
///     priority — explicit per-builder configuration wins over every other source).
///   </description></item>
///   <item><description>
///     <see cref="VellumEntityFrameworkOptionsAttribute"/> applied on the
///     <see cref="Microsoft.EntityFrameworkCore.DbContext"/> CLR type. Each property that
///     is non-<see langword="null"/> (or a positive integer for the length limits) overrides
///     the Vellum default; every unset property falls back to the built-in default. This
///     source is reflection-readable at design time and is the recommended way to declare
///     a stable schema shape that survives a custom
///     <see cref="Microsoft.EntityFrameworkCore.Design.IDesignTimeDbContextFactory{TContext}"/>.
///   </description></item>
///   <item><description>
///     <see cref="Microsoft.Extensions.Options.IOptions{TOptions}"/> from the application
///     service provider, as registered by
///     <see cref="VellumEntityFrameworkServiceCollectionExtensions.AddEntityFrameworkCoreStore{TContext}(Microsoft.Extensions.DependencyInjection.IServiceCollection, System.Action{VellumEntityFrameworkOptions}?)"/>.
///     Works at runtime when the context is built through
///     <c>AddDbContext&lt;T&gt;</c>; typically unavailable at design time.
///   </description></item>
///   <item><description>
///     A default-constructed <see cref="VellumEntityFrameworkOptions"/> (fallback).
///   </description></item>
/// </list>
/// <para>
/// <b>Partial overrides.</b> Every attribute property is nullable (or uses <c>0</c> as the
/// "not set" sentinel for the length limits). Leaving a property at its default lets
/// Vellum's default win for that property, so consumers can decorate their context with a
/// minimal attribute (<c>[VellumEntityFrameworkOptions(TableName = "bus_encryption_keys")]</c>
/// for example) without having to repeat every default column name.
/// </para>
/// <para>
/// <b>Filter + column-name coupling.</b> If you rename
/// <see cref="IsActiveColumnName"/>, update <see cref="UniqueActiveIndexFilter"/> in the
/// same attribute application to reference the new column name — same contract as
/// <see cref="VellumEntityFrameworkOptions.UniqueActiveIndexFilter"/>.
/// </para>
/// </remarks>
/// <example>
/// The jacqcloud-buses pattern: a snake_case PostgreSQL schema declared once on the
/// context type. Works in both <c>AddDbContext&lt;T&gt;</c> and
/// <see cref="Microsoft.EntityFrameworkCore.Design.IDesignTimeDbContextFactory{TContext}"/>.
/// <code>
/// [VellumEntityFrameworkOptions(
///     TableName = "bus_encryption_keys",
///     KeyIdColumnName = "key_id",
///     ScopeColumnName = "scope",
///     WrappedCiphertextColumnName = "wrapped_ciphertext",
///     WrappedProviderVersionColumnName = "wrapped_provider_version",
///     CreatedAtColumnName = "created_at",
///     ExpiresAtColumnName = "expires_at",
///     IsActiveColumnName = "is_active",
///     UniqueActiveIndexFilter = "\"is_active\" = true")]
/// public sealed class RuntimeDbContext(DbContextOptions&lt;RuntimeDbContext&gt; options)
///     : DbContext(options)
/// {
///     protected override void OnModelCreating(ModelBuilder modelBuilder)
///     {
///         base.OnModelCreating(modelBuilder);
///         modelBuilder.AddVellumEncryptionKeys(this);
///     }
/// }
/// </code>
/// </example>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class VellumEntityFrameworkOptionsAttribute : Attribute
{
    /// <summary>
    /// Gets or sets the table name used for the wrapped Data Encryption Key storage.
    /// Leaving this <see langword="null"/> falls back to the Vellum default
    /// (<c>vellum_encryption_keys</c>).
    /// </summary>
    public string? TableName { get; set; }

    /// <summary>
    /// Gets or sets the schema name for the encryption key table. Leaving this
    /// <see langword="null"/> uses the provider-default schema (for example <c>dbo</c>
    /// on SQL Server or <c>public</c> on PostgreSQL).
    /// </summary>
    public string? SchemaName { get; set; }

    /// <summary>
    /// Gets or sets the SQL fragment used as the filter of the "only one active key per
    /// scope" unique index. Leaving this <see langword="null"/> falls back to the Vellum
    /// default (<c>[IsActive] = 1</c>, SQL Server syntax). See
    /// <see cref="VellumEntityFrameworkOptions.UniqueActiveIndexFilter"/> for the
    /// per-provider syntax.
    /// </summary>
    public string? UniqueActiveIndexFilter { get; set; }

    /// <summary>
    /// Gets or sets the maximum length of the <c>Scope</c> column. Leaving this
    /// <c>0</c> falls back to the Vellum default (256). Negative values are rejected at
    /// model-build time by Vellum's options validator.
    /// </summary>
    public int ScopeMaxLength { get; set; }

    /// <summary>
    /// Gets or sets the maximum length of the KEK provider version column. Leaving this
    /// <c>0</c> falls back to the Vellum default (512).
    /// </summary>
    public int WrappedProviderVersionMaxLength { get; set; }

    /// <summary>
    /// Gets or sets the column name for the DEK identifier. Leaving this
    /// <see langword="null"/> falls back to <c>KeyId</c>.
    /// </summary>
    public string? KeyIdColumnName { get; set; }

    /// <summary>
    /// Gets or sets the column name for the opaque scope identifier. Leaving this
    /// <see langword="null"/> falls back to <c>Scope</c>.
    /// </summary>
    public string? ScopeColumnName { get; set; }

    /// <summary>
    /// Gets or sets the column name for the wrapped DEK ciphertext. Leaving this
    /// <see langword="null"/> falls back to <c>WrappedCiphertext</c>.
    /// </summary>
    public string? WrappedCiphertextColumnName { get; set; }

    /// <summary>
    /// Gets or sets the column name for the KEK provider version. Leaving this
    /// <see langword="null"/> falls back to <c>WrappedProviderVersion</c>.
    /// </summary>
    public string? WrappedProviderVersionColumnName { get; set; }

    /// <summary>
    /// Gets or sets the column name for the creation timestamp. Leaving this
    /// <see langword="null"/> falls back to <c>CreatedAt</c>.
    /// </summary>
    public string? CreatedAtColumnName { get; set; }

    /// <summary>
    /// Gets or sets the column name for the optional expiry timestamp. Leaving this
    /// <see langword="null"/> falls back to <c>ExpiresAt</c>.
    /// </summary>
    public string? ExpiresAtColumnName { get; set; }

    /// <summary>
    /// Gets or sets the column name for the active flag. Leaving this
    /// <see langword="null"/> falls back to <c>IsActive</c>. When you rename this column,
    /// update <see cref="UniqueActiveIndexFilter"/> in the same attribute application to
    /// reference the new column name.
    /// </summary>
    public string? IsActiveColumnName { get; set; }
}
