using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
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
/// <b>Single-source options (issue #9).</b> The extension resolves
/// <see cref="VellumEntityFrameworkOptions"/> at model-build time from the owning
/// <see cref="DbContext"/>, so the consumer no longer has to pass the options literal here
/// <i>and</i> to <c>AddEntityFrameworkCoreStore&lt;T&gt;</c>. Resolution order:
/// </para>
/// <list type="number">
///   <item><description>
///     Options attached via
///     <see cref="VellumDbContextOptionsBuilderExtensions.UseVellum(DbContextOptionsBuilder, Action{VellumEntityFrameworkOptions}?)"/>
///     on the <see cref="DbContextOptionsBuilder"/> (highest priority — explicit
///     per-context configuration).
///   </description></item>
///   <item><description>
///     <see cref="IOptions{TOptions}"/> from the application service provider, as
///     registered by <see cref="VellumEntityFrameworkServiceCollectionExtensions.AddEntityFrameworkCoreStore{TContext}(IServiceCollection, Action{VellumEntityFrameworkOptions}?)"/>
///     (works when the context is built through <c>AddDbContext&lt;T&gt;</c>).
///   </description></item>
///   <item><description>
///     A default-constructed <see cref="VellumEntityFrameworkOptions"/> (fallback so the
///     extension never throws at model-build time — the validator still fires at host start
///     if the consumer registered <c>AddEntityFrameworkCoreStore</c>).
///   </description></item>
/// </list>
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
    /// Registers the internal wrapped-DEK entity on the given <see cref="ModelBuilder"/>,
    /// resolving <see cref="VellumEntityFrameworkOptions"/> from the owning
    /// <paramref name="context"/>.
    /// </summary>
    /// <param name="modelBuilder">The EF Core model builder.</param>
    /// <param name="context">
    /// The <see cref="DbContext"/> whose model is being built. Typically <c>this</c> inside
    /// <c>OnModelCreating</c>. Used to resolve the Vellum options (see the type-level remarks
    /// for the resolution order).
    /// </param>
    /// <returns>The same <see cref="ModelBuilder"/> so calls can be chained.</returns>
    public static ModelBuilder AddVellumEncryptionKeys(
        this ModelBuilder modelBuilder,
        DbContext context)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        ArgumentNullException.ThrowIfNull(context);

        VellumEntityFrameworkOptions options = ResolveOptions(context);
        modelBuilder.Entity<EncryptionKeyRecord>(entity => Configure(entity, options));

        return modelBuilder;
    }

    /// <summary>
    /// Registers the internal wrapped-DEK entity on the given <see cref="ModelBuilder"/>
    /// with an explicit options literal. Prefer
    /// <see cref="AddVellumEncryptionKeys(ModelBuilder, DbContext)"/> for production code
    /// — this overload exists for design-time tooling and tests that do not flow options
    /// through DI or <c>UseVellum</c>.
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

    private static VellumEntityFrameworkOptions ResolveOptions(DbContext context)
    {
        // Priority 1: explicit per-context options attached via UseVellum.
        IDbContextOptions dbContextOptions = context.GetService<IDbContextOptions>();
        VellumDbContextOptionsExtension? contextExtension =
            dbContextOptions.FindExtension<VellumDbContextOptionsExtension>();
        if (contextExtension is not null)
        {
            return contextExtension.Options;
        }

        // Priority 2: IOptions<T> from the application service provider (populated by
        // AddEntityFrameworkCoreStore when the context is built through AddDbContext<T>).
        CoreOptionsExtension? core = dbContextOptions.FindExtension<CoreOptionsExtension>();
        IServiceProvider? appServices = core?.ApplicationServiceProvider;
        VellumEntityFrameworkOptions? fromDi = appServices
            ?.GetService<IOptions<VellumEntityFrameworkOptions>>()
            ?.Value;
        if (fromDi is not null)
        {
            return fromDi;
        }

        // Priority 3: defaults. Consumers who hit this path without also calling UseVellum
        // or AddEntityFrameworkCoreStore get the out-of-the-box PascalCase / SQL-Server
        // shape — same result as passing `new VellumEntityFrameworkOptions()` explicitly.
        return new VellumEntityFrameworkOptions();
    }

    private static void Configure(
        EntityTypeBuilder<EncryptionKeyRecord> entity,
        VellumEntityFrameworkOptions options)
    {
        entity.ToTable(options.TableName, options.SchemaName);

        entity.HasKey(k => k.KeyId);

        entity.Property(k => k.KeyId)
            .HasColumnName(options.KeyIdColumnName)
            .ValueGeneratedNever();

        entity.Property(k => k.Scope)
            .HasColumnName(options.ScopeColumnName)
            .IsRequired()
            .HasMaxLength(options.ScopeMaxLength);

        entity.Property(k => k.WrappedCiphertext)
            .HasColumnName(options.WrappedCiphertextColumnName)
            .IsRequired();

        entity.Property(k => k.WrappedProviderVersion)
            .HasColumnName(options.WrappedProviderVersionColumnName)
            .IsRequired()
            .HasMaxLength(options.WrappedProviderVersionMaxLength);

        entity.Property(k => k.CreatedAt)
            .HasColumnName(options.CreatedAtColumnName)
            .IsRequired();

        entity.Property(k => k.ExpiresAt)
            .HasColumnName(options.ExpiresAtColumnName);

        entity.Property(k => k.IsActive)
            .HasColumnName(options.IsActiveColumnName)
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
