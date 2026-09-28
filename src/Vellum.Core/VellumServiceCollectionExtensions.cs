using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Vellum;

/// <summary>
/// <see cref="IServiceCollection"/> extensions for registering the Vellum core services.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="AddVellum"/> also calls
/// <see cref="VellumDecryptMetrics.EnsureInstrumentsPublished"/>, so the decrypt instruments are
/// exported from startup rather than from the first decrypt.
/// </para>
/// <para>
/// <see cref="AddVellum"/> wires up <see cref="IDekManager"/>, <see cref="IPayloadEncryptor"/>,
/// <see cref="VellumRewrapService"/>, <see cref="IRandomBytesProvider"/> and
/// <see cref="TimeProvider"/> — plus the Vellum-owned
/// <see cref="VellumDekCache"/> used on the hot path. It deliberately does <b>not</b> register
/// or touch the application's shared <c>IMemoryCache</c>: plaintext DEKs live in a dedicated
/// cache that only Vellum can reach (M-C). It also does <b>not</b> register an
/// <see cref="IKeyEncryptionProvider"/> or an <see cref="IEncryptionKeyStore"/>; consumers are
/// expected to pull in a provider package (for example, <c>Vellum.Vault</c>) and a storage
/// package (for example, <c>Vellum.EntityFrameworkCore</c>) and call their respective
/// registration extensions.
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

        // NOT DEAD CODE — DO NOT REMOVE. This builds the decrypt Meter and publishes its five
        // instruments now, at registration time, instead of on the first decrypt. Read
        // EnsureInstrumentsPublished's own documentation before touching this line: it has no
        // visible effect, which is exactly why it gets deleted by accident, and deleting it breaks
        // observability with no compiler error. Guarded by Vellum.Core.MeterRegistration.Tests.
        VellumDecryptMetrics.EnsureInstrumentsPublished();

        services.AddOptions<VellumOptions>();
        if (configureOptions is not null)
        {
            services.Configure(configureOptions);
        }

        // M-C: the DEK cache is a Vellum-owned singleton, NEVER the application's shared
        // IMemoryCache — arbitrary in-process code resolving IMemoryCache must not be able to
        // read plaintext DEKs, and consumer SizeLimit budgeting/compaction must not evict them.
        // Singleton so cached DEKs survive across DI scopes (DekManager itself stays scoped for
        // EF-backed stores); the container disposes it on shutdown, scrubbing remaining entries.
        services.TryAddSingleton<VellumDekCache>();

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IRandomBytesProvider, DefaultRandomBytesProvider>();

        // Scoped lifetimes so that EF-Core-backed IEncryptionKeyStore implementations
        // (which typically depend on a scoped DbContext) are not captured by a singleton.
        services.TryAddScoped<IDekManager, DekManager>();
        services.TryAddScoped<IPayloadEncryptor, PayloadEncryptor>();
        services.TryAddScoped<VellumRewrapService>();

        return services;
    }
}
