using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Vellum;

/// <summary>
/// <see cref="IServiceCollection"/> extensions for registering the Vellum core services.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="AddVellum"/> wires up <see cref="IDekManager"/>, <see cref="IPayloadEncryptor"/>,
/// <see cref="IRandomBytesProvider"/> and <see cref="TimeProvider"/> — plus the in-memory cache
/// used on the hot path. It does <b>not</b> register an <see cref="IKeyEncryptionProvider"/>
/// or an <see cref="IEncryptionKeyStore"/>; consumers are expected to pull in a provider
/// package (for example, <c>Vellum.Vault</c>) and a storage package (for example,
/// <c>Vellum.EntityFrameworkCore</c>) and call their respective registration extensions.
/// </para>
/// <para>
/// The method uses <see cref="ServiceCollectionDescriptorExtensions.TryAdd(IServiceCollection, ServiceDescriptor)"/>
/// variants so that consumers can override any Vellum-provided service by registering their
/// own implementation <i>before</i> calling <see cref="AddVellum"/>.
/// </para>
/// </remarks>
public static class VellumServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Vellum core services into the <see cref="IServiceCollection"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Optional delegate to configure <see cref="VellumOptions"/>.</param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is <see langword="null"/>.</exception>
    public static IServiceCollection AddVellum(
        this IServiceCollection services,
        Action<VellumOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<VellumOptions>();
        if (configureOptions is not null)
        {
            services.Configure(configureOptions);
        }

        services.AddMemoryCache();

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IRandomBytesProvider, DefaultRandomBytesProvider>();

        // Scoped lifetimes so that EF-Core-backed IEncryptionKeyStore implementations
        // (which typically depend on a scoped DbContext) are not captured by a singleton.
        services.TryAddScoped<IDekManager, DekManager>();
        services.TryAddScoped<IPayloadEncryptor, PayloadEncryptor>();

        return services;
    }
}
