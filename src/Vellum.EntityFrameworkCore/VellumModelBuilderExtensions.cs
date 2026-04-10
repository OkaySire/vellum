using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Vellum.EntityFrameworkCore.Internal;

namespace Vellum.EntityFrameworkCore;

/// <summary>
/// Registers the Vellum wrapped-DEK entity on an EF Core <see cref="ModelBuilder"/>.
/// </summary>
/// <remarks>
/// <para>
/// Consumers wire this extension into their own <c>DbContext.OnModelCreating</c> so that
/// the wrapped-DEK table is created by the consumer's normal EF Core migrations pipeline
/// alongside the rest of their schema. Vellum does not ship migrations of its own — the
/// schema is small enough (one table, one filtered unique index, one scope index) that
/// generating them with the consumer's existing tooling is the least-surprising path.
/// </para>
/// <para>
/// Call the extension once, after any tenant-filter configuration, to make sure the
/// wrapped-DEK table inherits the consumer's schema conventions but no global query filter.
/// Vellum's store reads are already unconditional via <c>IgnoreQueryFilters()</c>, so a
/// tenant filter applied to this entity would be silently ignored — better not to add one.
/// </para>
/// </remarks>
public static class VellumModelBuilderExtensions
{
    /// <summary>
    /// Registers the internal wrapped-DEK entity on the given <see cref="ModelBuilder"/>.
    /// </summary>
    /// <param name="modelBuilder">The EF Core model builder.</param>
    /// <param name="options">The Vellum EF Core options controlling table name, schema, filter, and column sizes.</param>
    /// <returns>The same <see cref="ModelBuilder"/> so calls can be chained.</returns>
    public static ModelBuilder AddVellumEncryptionKeys(
        this ModelBuilder modelBuilder,
        VellumEntityFrameworkOptions options)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        ArgumentNullException.ThrowIfNull(options);

        modelBuilder.Entity<EncryptionKeyRecord>(entity => Configure(entity, options));

        return modelBuilder;
    }

    private static void Configure(
        EntityTypeBuilder<EncryptionKeyRecord> entity,
        VellumEntityFrameworkOptions options)
    {
        entity.ToTable(options.TableName, options.SchemaName);

        entity.HasKey(k => k.KeyId);

        entity.Property(k => k.KeyId)
            .ValueGeneratedNever();

        entity.Property(k => k.Scope)
            .IsRequired()
            .HasMaxLength(options.ScopeMaxLength);

        entity.Property(k => k.WrappedCiphertext)
            .IsRequired();

        entity.Property(k => k.WrappedProviderVersion)
            .IsRequired()
            .HasMaxLength(options.WrappedProviderVersionMaxLength);

        entity.Property(k => k.CreatedAt)
            .IsRequired();

        entity.Property(k => k.IsActive)
            .IsRequired();

        // Non-unique index on Scope for fast lookups of historical keys and active-by-scope.
        entity.HasIndex(k => k.Scope);

        // Filtered unique index enforces "one active key per scope" at the database level.
        // The SQL filter fragment is provider-specific — consumers override it via
        // VellumEntityFrameworkOptions.UniqueActiveIndexFilter. See the XML remarks on
        // VellumEntityFrameworkOptions for the per-provider syntax.
        entity.HasIndex(k => k.Scope)
            .HasDatabaseName("IX_vellum_encryption_keys_Scope_Active")
            .HasFilter(options.UniqueActiveIndexFilter)
            .IsUnique();
    }
}
