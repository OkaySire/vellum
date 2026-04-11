using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Vellum.EntityFrameworkCore.Internal;

namespace Vellum.EntityFrameworkCore;

/// <summary>
/// Registration helpers for <see cref="EntityFrameworkCoreEncryptionKeyStore{TContext}"/>.
/// </summary>
public static class VellumEntityFrameworkServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Entity Framework Core-backed <see cref="IEncryptionKeyStore"/> using the
    /// consumer's <typeparamref name="TContext"/> as the transport. The consumer must also call
    /// <c>modelBuilder.AddVellumEncryptionKeys(this)</c> in <c>TContext.OnModelCreating</c>
    /// so that EF Core knows about the wrapped-DEK table.
    /// </summary>
    /// <typeparam name="TContext">The consumer's <see cref="DbContext"/> subclass.</typeparam>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configure">Optional delegate to customise <see cref="VellumEntityFrameworkOptions"/>.</param>
    /// <returns>The same <see cref="IServiceCollection"/> so calls can be chained.</returns>
    /// <remarks>
    /// <para>
    /// The store is registered as <b>Scoped</b>. This matches the lifetime of the
    /// <typeparamref name="TContext"/> instance it resolves from the container — sharing a
    /// store across scopes would mean sharing a <see cref="DbContext"/> across scopes, which
    /// is neither safe nor supported.
    /// </para>
    /// <para>
    /// <c>TryAdd</c> semantics are preserved: if the consuming application has already
    /// registered its own <see cref="IEncryptionKeyStore"/>, this call will not override it.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddEntityFrameworkCoreStore<TContext>(
        this IServiceCollection services,
        Action<VellumEntityFrameworkOptions>? configure = null)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<VellumEntityFrameworkOptions>()
            .Configure(configure ?? (_ => { }))
            .ValidateOnStart();

        // M-7: bring EF Core in line with Vellum.Static and Vellum.Vault, both of which
        // validate options on start. Misconfigurations like an empty TableName or a
        // zero-length scope fail here rather than later inside OnModelCreating.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<VellumEntityFrameworkOptions>, VellumEntityFrameworkOptionsValidator>());

        services.TryAddScoped<EntityFrameworkCoreEncryptionKeyStore<TContext>>();
        services.TryAddScoped<IEncryptionKeyStore>(sp =>
            sp.GetRequiredService<EntityFrameworkCoreEncryptionKeyStore<TContext>>());

        return services;
    }
}
