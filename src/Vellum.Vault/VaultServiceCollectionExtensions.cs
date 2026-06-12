using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Vellum.Vault.Internal;

namespace Vellum.Vault;

/// <summary>
/// Registration helpers for the HashiCorp Vault Transit key encryption provider.
/// </summary>
public static partial class VaultServiceCollectionExtensions
{
    private const string _vaultTokenHeaderName = "X-Vault-Token";

    /// <summary>
    /// M-E: hard cap on the number of bytes the <see cref="HttpClient"/> will buffer from any
    /// Vault response. Legitimate Transit wrap/unwrap responses are small JSON documents (a
    /// wrapped 32-byte DEK in base64 plus metadata — well under 4 KB), so 64 KB is generous.
    /// A malicious or compromised Vault returning a multi-gigabyte body causes an
    /// <see cref="HttpRequestException"/> instead of an unbounded allocation — fail closed.
    /// </summary>
    private const long _maxResponseContentBufferBytes = 64 * 1024;

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
    /// <para>
    /// <b>H-B: token redaction.</b> The <c>X-Vault-Token</c> header lives in
    /// <see cref="HttpClient.DefaultRequestHeaders"/>, and the default
    /// <see cref="IHttpClientFactory"/> logging handlers log all request headers at Trace level.
    /// This registration calls <c>RedactLoggedHeaders</c> so the token value is replaced with
    /// <c>*</c> in every <see cref="IHttpClientFactory"/> log entry, on every target framework
    /// (the API ships in the Microsoft.Extensions.Http package referenced for all TFMs).
    /// </para>
    /// <para>
    /// <b>M-E: bounded response buffering.</b> <see cref="HttpClient.MaxResponseContentBufferSize"/>
    /// is capped at 64 KB. Legitimate Transit responses are tiny JSON; a response exceeding the
    /// cap throws <see cref="HttpRequestException"/> rather than allocating attacker-controlled
    /// amounts of memory — fail closed.
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

        IHttpClientBuilder httpClientBuilder = services.AddHttpClient<VaultKeyEncryptionProvider>((sp, client) =>
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

            Uri baseAddress = new(opts.Address.EndsWith('/') ? opts.Address : opts.Address + "/");

            // H-A: validation above guarantees an http:// scheme only ever reaches this point
            // when AllowInsecureHttp was explicitly opted into. Warn loudly every time an
            // insecure client is constructed; only the host is logged — never the token.
            if (baseAddress.Scheme == Uri.UriSchemeHttp)
            {
                ILogger<VaultKeyEncryptionProvider> logger =
                    sp.GetRequiredService<ILogger<VaultKeyEncryptionProvider>>();
                LogInsecureHttpEnabled(logger, baseAddress.Host);
            }

            client.BaseAddress = baseAddress;
            client.Timeout = opts.HttpTimeout;
            client.MaxResponseContentBufferSize = _maxResponseContentBufferBytes;
            client.DefaultRequestHeaders.Remove(_vaultTokenHeaderName);
            client.DefaultRequestHeaders.Add(_vaultTokenHeaderName, opts.Token);
        });

        // H-B: the default IHttpClientFactory logging handlers would otherwise log the
        // X-Vault-Token value verbatim at Trace level.
        httpClientBuilder.RedactLoggedHeaders([_vaultTokenHeaderName]);

        services.TryAddTransient<IKeyEncryptionProvider>(sp => sp.GetRequiredService<VaultKeyEncryptionProvider>());

        return services;
    }

    // EventId 5 continues the "Vellum.Vault.VaultKeyEncryptionProvider" logger-category
    // sequence: EventIds 1-4 are emitted by VaultKeyEncryptionProvider itself.
    [LoggerMessage(
        EventId = 5,
        Level = LogLevel.Warning,
        Message = "Vault address for host '{Host}' uses plain http:// (AllowInsecureHttp = true). " +
                  "The Vault token and plaintext DEKs are transmitted in CLEARTEXT. " +
                  "This is acceptable only against a local 'vault server -dev'; use https:// everywhere else.")]
    private static partial void LogInsecureHttpEnabled(ILogger logger, string host);
}
