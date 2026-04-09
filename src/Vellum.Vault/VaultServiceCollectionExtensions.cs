using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Vellum.Vault.Internal;

namespace Vellum.Vault;

/// <summary>
/// Registration helpers for the HashiCorp Vault Transit key encryption provider.
/// </summary>
public static class VaultServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="VaultKeyEncryptionProvider"/> as the <see cref="IKeyEncryptionProvider"/>
    /// and wires up a typed <see cref="HttpClient"/> against the configured Vault server.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configure">
    /// An action that populates <see cref="VaultOptions"/>. All three required fields (Address,
    /// Token, KeyName) are validated at <c>ValidateOnStart()</c> time — a missing value will
    /// cause the host to fail fast.
    /// </param>
    /// <returns>The same <see cref="IServiceCollection"/> so calls can be chained.</returns>
    /// <remarks>
    /// <para>
    /// The typed <see cref="HttpClient"/> is registered as Transient (the default for
    /// <see cref="HttpClientFactoryServiceCollectionExtensions.AddHttpClient{TClient}(IServiceCollection)"/>)
    /// so that handler rotation works correctly. The <see cref="IKeyEncryptionProvider"/> bridge
    /// mirrors that lifetime: each resolution hands back a fresh <see cref="VaultKeyEncryptionProvider"/>
    /// bound to a current <see cref="HttpClient"/>.
    /// </para>
    /// <para>
    /// <c>TryAdd</c> semantics are preserved: if the consuming application has already registered
    /// its own <see cref="IKeyEncryptionProvider"/>, this call will not override it.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddVaultProvider(
        this IServiceCollection services,
        Action<VaultOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<VaultOptions>()
            .Configure(configure)
            .ValidateOnStart();

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<VaultOptions>, VaultOptionsValidator>());

        services.AddHttpClient<VaultKeyEncryptionProvider>((sp, client) =>
        {
            VaultOptions opts = sp.GetRequiredService<IOptions<VaultOptions>>().Value;

            // Re-run validation here so the exception at construction time is identical to the
            // ValidateOnStart() message if the consumer disables start-up validation.
            ValidateOptionsResult validation = new VaultOptionsValidator().Validate(Options.DefaultName, opts);
            if (validation.Failed)
            {
                throw new OptionsValidationException(
                    Options.DefaultName,
                    typeof(VaultOptions),
                    validation.Failures ?? []);
            }

            client.BaseAddress = new Uri(opts.Address.EndsWith('/') ? opts.Address : opts.Address + "/");
            client.Timeout = opts.HttpTimeout;
            client.DefaultRequestHeaders.Remove("X-Vault-Token");
            client.DefaultRequestHeaders.Add("X-Vault-Token", opts.Token);
        });

        services.TryAddTransient<IKeyEncryptionProvider>(sp => sp.GetRequiredService<VaultKeyEncryptionProvider>());

        return services;
    }
}
