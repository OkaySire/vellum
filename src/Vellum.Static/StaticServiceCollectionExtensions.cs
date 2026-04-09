using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Vellum.Static.Internal;

namespace Vellum.Static;

/// <summary>
/// Registration helpers for the <see cref="StaticKeyEncryptionProvider"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>⚠️ DEVELOPMENT USE ONLY ⚠️</b>
/// </para>
/// <para>
/// This extension wires up a KEK provider whose Key Encryption Key lives in configuration. It
/// is intended for local development, tests, and samples. <b>Never</b> call it in production:
/// the KEK will be as visible as the config file that holds it (which, in practice, means logs,
/// crash dumps, CI artefacts, and backups).
/// </para>
/// <para>
/// For production, use <c>AddVaultProvider</c>, <c>AddAzureKeyVaultProvider</c>,
/// <c>AddAwsKmsProvider</c>, or <c>AddGcpKmsProvider</c>.
/// </para>
/// </remarks>
public static class StaticServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="StaticKeyEncryptionProvider"/> as the <see cref="IKeyEncryptionProvider"/>
    /// implementation, wiring up options, validation, and the development-use warning logger.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configure">
    /// An action that populates <see cref="StaticOptions"/>. The single required field is
    /// <see cref="StaticOptions.Base64Key"/>, which must decode to exactly 32 bytes.
    /// </param>
    /// <returns>The same <see cref="IServiceCollection"/> so calls can be chained.</returns>
    /// <remarks>
    /// <para>
    /// <b>⚠️ DEVELOPMENT USE ONLY ⚠️</b> — see the type-level remarks on
    /// <see cref="StaticServiceCollectionExtensions"/> and <see cref="StaticKeyEncryptionProvider"/>
    /// for the full warning.
    /// </para>
    /// <para>
    /// <b>Example configuration.</b> Generate a KEK with
    /// <c>openssl rand -base64 32</c> (or the .NET equivalent) and pass it to the configure
    /// delegate:
    /// </para>
    /// <code>
    /// services.AddStaticProvider(options =&gt;
    /// {
    ///     options.Base64Key = "&lt;base64 of 32 random bytes&gt;";
    /// });
    /// </code>
    /// <para>
    /// Validation (base64 decodes, length equals 32 bytes) runs at <c>ValidateOnStart()</c> time,
    /// so a host that boots successfully is guaranteed to have a usable KEK. The base64 value
    /// itself is never included in validation or log messages, but it <b>will</b> be visible in
    /// any process dump, environment variable listing, or config reader — treat the config source
    /// the same way you would treat the raw key.
    /// </para>
    /// <para>
    /// <c>TryAdd</c> semantics are preserved: if the consuming application has already registered
    /// its own <see cref="IKeyEncryptionProvider"/>, this call will not override it.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddStaticProvider(
        this IServiceCollection services,
        Action<StaticOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<StaticOptions>()
            .Configure(configure)
            .ValidateOnStart();

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<StaticOptions>, StaticOptionsValidator>());

        services.TryAddSingleton<StaticKeyEncryptionProvider>();
        services.TryAddSingleton<IKeyEncryptionProvider>(sp => sp.GetRequiredService<StaticKeyEncryptionProvider>());

        return services;
    }
}
