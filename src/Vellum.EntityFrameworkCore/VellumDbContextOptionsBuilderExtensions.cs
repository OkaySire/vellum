using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Vellum.EntityFrameworkCore.Internal;

namespace Vellum.EntityFrameworkCore;

/// <summary>
/// Extension methods that attach <see cref="VellumEntityFrameworkOptions"/> to a
/// <see cref="DbContextOptionsBuilder"/>. Once attached, the options flow through
/// <c>modelBuilder.AddVellumEncryptionKeys(this)</c> inside <c>DbContext.OnModelCreating</c>
/// — no second literal, no hand-duplicated configuration.
/// </summary>
/// <remarks>
/// <para>
/// Issue #9 (move options source to DI). The canonical pattern is:
/// </para>
/// <code>
/// services.AddDbContext&lt;AppDbContext&gt;(options =&gt; options
///     .UseNpgsql(connectionString)
///     .UseVellum(v =&gt;
///     {
///         v.TableName = "bus_encryption_keys";
///         v.UniqueActiveIndexFilter = "\"IsActive\" = true";
///     }));
/// services.AddEntityFrameworkCoreStore&lt;AppDbContext&gt;();
/// </code>
/// <para>
/// Inside <c>AppDbContext.OnModelCreating</c>, the consumer then writes:
/// </para>
/// <code>
/// protected override void OnModelCreating(ModelBuilder modelBuilder)
/// {
///     base.OnModelCreating(modelBuilder);
///     modelBuilder.AddVellumEncryptionKeys(this);
/// }
/// </code>
/// </remarks>
public static class VellumDbContextOptionsBuilderExtensions
{
    /// <summary>
    /// Attaches <see cref="VellumEntityFrameworkOptions"/> to the
    /// <see cref="DbContextOptionsBuilder"/>, optionally applying a configure delegate.
    /// </summary>
    /// <param name="optionsBuilder">The EF Core options builder.</param>
    /// <param name="configure">Optional delegate to customise the options.</param>
    /// <returns>The same <see cref="DbContextOptionsBuilder"/> so calls can be chained.</returns>
    /// <remarks>
    /// Calling <c>UseVellum</c> multiple times is idempotent: the latest call replaces the
    /// previously attached extension. If the consumer never calls <c>UseVellum</c>, the
    /// model builder extension falls back to <see cref="VellumEntityFrameworkOptions"/>
    /// resolved from the application service provider (<c>IOptions&lt;T&gt;</c> registered by
    /// <see cref="VellumEntityFrameworkServiceCollectionExtensions.AddEntityFrameworkCoreStore{TContext}"/>)
    /// and, failing that, to a default instance.
    /// </remarks>
    public static DbContextOptionsBuilder UseVellum(
        this DbContextOptionsBuilder optionsBuilder,
        Action<VellumEntityFrameworkOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(optionsBuilder);

        VellumEntityFrameworkOptions options = new();
        configure?.Invoke(options);

        ((IDbContextOptionsBuilderInfrastructure)optionsBuilder)
            .AddOrUpdateExtension(new VellumDbContextOptionsExtension(options));

        return optionsBuilder;
    }

    /// <summary>
    /// Typed overload of <see cref="UseVellum(DbContextOptionsBuilder, Action{VellumEntityFrameworkOptions}?)"/>
    /// that preserves fluent chaining on <see cref="DbContextOptionsBuilder{TContext}"/>.
    /// </summary>
    /// <typeparam name="TContext">The consumer's <see cref="DbContext"/> subclass.</typeparam>
    /// <param name="optionsBuilder">The typed EF Core options builder.</param>
    /// <param name="configure">Optional delegate to customise the options.</param>
    /// <returns>The same <see cref="DbContextOptionsBuilder{TContext}"/> so calls can be chained.</returns>
    public static DbContextOptionsBuilder<TContext> UseVellum<TContext>(
        this DbContextOptionsBuilder<TContext> optionsBuilder,
        Action<VellumEntityFrameworkOptions>? configure = null)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(optionsBuilder);
        UseVellum((DbContextOptionsBuilder)optionsBuilder, configure);
        return optionsBuilder;
    }
}
