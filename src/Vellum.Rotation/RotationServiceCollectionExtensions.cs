using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Vellum.Rotation.Internal;

namespace Vellum.Rotation;

/// <summary>
/// Registration helpers for the opt-in <see cref="DekRotationBackgroundService"/>.
/// </summary>
/// <remarks>
/// Rotation is deliberately not part of <c>Vellum.Core</c> — consumers who do not want a
/// background service in their process simply never call <see cref="AddVellumRotation"/> and
/// rotate manually via <see cref="IDekManager.RotateDekAsync"/> instead.
/// </remarks>
public static class RotationServiceCollectionExtensions
{
    /// <summary>
    /// Registers the <see cref="DekRotationBackgroundService"/> hosted service together with
    /// <see cref="RotationOptions"/> and its start-up validation.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configure">
    /// Optional delegate to configure <see cref="RotationOptions"/>. When omitted, the defaults
    /// apply (24 h interval, 24 h max DEK age, 3 retries per scope, 5 s retry base delay,
    /// 1 min startup delay).
    /// </param>
    /// <returns>The same <see cref="IServiceCollection"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// <para>
    /// Requires <c>AddVellum()</c> (or equivalent registrations of <see cref="IDekManager"/> and
    /// <see cref="IEncryptionKeyStore"/>) plus a KEK provider and a key store package. The worker
    /// resolves <see cref="IDekManager"/> and <see cref="IEncryptionKeyStore"/> from a fresh DI
    /// scope on every tick, matching the scoped lifetimes registered by <c>AddVellum()</c>.
    /// </para>
    /// <para>
    /// Options are validated at host start via <c>ValidateOnStart()</c>; an invalid configuration
    /// (non-positive interval, negative retry count, ...) prevents the host from starting rather
    /// than producing a worker that silently never rotates.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddVellumRotation(
        this IServiceCollection services,
        Action<RotationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        OptionsBuilder<RotationOptions> optionsBuilder = services.AddOptions<RotationOptions>();
        if (configure is not null)
        {
            optionsBuilder.Configure(configure);
        }

        optionsBuilder.ValidateOnStart();

        // L18: TryAddEnumerable requires the type-parameter overload — a factory registration
        // has no ImplementationType and is rejected as "indistinguishable" at runtime.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<RotationOptions>, RotationOptionsValidator>());

        services.TryAddSingleton(TimeProvider.System);
        services.AddHostedService<DekRotationBackgroundService>();

        return services;
    }
}
