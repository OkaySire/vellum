using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Vellum.Vault.Internal;

namespace Vellum.Vault;

/// <summary>
/// Registration helpers for the HashiCorp Vault Transit key encryption provider.
/// </summary>
public static partial class VaultServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="VaultKeyEncryptionProvider"/> as the <see cref="IKeyEncryptionProvider"/>
    /// and wires up a typed <see cref="HttpClient"/> against the configured Vault server.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configure">
    /// An action that populates <see cref="VaultOptions"/>. The required fields (Address,
    /// KeyName, plus the credentials matching <see cref="VaultOptions.AuthMethod"/>) are
    /// validated at <c>ValidateOnStart()</c> time — a missing value will cause the host to
    /// fail fast.
    /// </param>
    /// <returns>The same <see cref="IServiceCollection"/> so calls can be chained.</returns>
    /// <remarks>
    /// <para>
    /// <b>Handler pipeline (outermost first):</b> standard resilience handler (when
    /// <see cref="VaultOptions.EnableResilience"/>, the default) → <see cref="VaultAuthenticationHandler"/>
    /// → transport. The auth handler sits <b>inside</b> the resilience handler deliberately:
    /// every retry attempt re-enters the auth handler, so each attempt gets a fresh-token
    /// opportunity (an attempt that failed because the token expired mid-flight is retried
    /// with a newly acquired token rather than replaying the stale one).
    /// </para>
    /// <para>
    /// <b>Authentication.</b> The <c>X-Vault-Token</c> header is stamped per request by
    /// <see cref="VaultAuthenticationHandler"/> from the singleton <see cref="IVaultTokenProvider"/>
    /// (selected by <see cref="VaultOptions.AuthMethod"/>; <c>TryAdd</c> semantics let consumers
    /// substitute their own provider). The token provider must be a singleton so its token cache
    /// is shared across the transient typed clients handed out by the factory. AppRole logins use
    /// a separate named client (<c>Vellum.Vault.AppRoleLogin</c>) that does not carry the auth
    /// handler — no recursion.
    /// </para>
    /// <para>
    /// The typed <see cref="HttpClient"/> is registered as Transient (the default for
    /// <see cref="HttpClientFactoryServiceCollectionExtensions.AddHttpClient{TClient}(IServiceCollection)"/>)
    /// so that handler rotation works correctly. The <see cref="IKeyEncryptionProvider"/> bridge
    /// mirrors that lifetime: each resolution hands back a fresh <see cref="VaultKeyEncryptionProvider"/>
    /// bound to a current <see cref="HttpClient"/>.
    /// </para>
    /// <para>
    /// <c>TryAdd</c> semantics are preserved: if the consuming application has already registered
    /// its own <see cref="IKeyEncryptionProvider"/> or <see cref="IVaultTokenProvider"/>, this
    /// call will not override them.
    /// </para>
    /// <para>
    /// <b>H-B: token redaction.</b> The default <see cref="IHttpClientFactory"/> logging handlers
    /// log all request headers at Trace level. This registration calls <c>RedactLoggedHeaders</c>
    /// (matching by header name, so the per-request header set by
    /// <see cref="VaultAuthenticationHandler"/> is covered) so the token value is replaced with
    /// <c>*</c> in every <see cref="IHttpClientFactory"/> log entry, on every target framework.
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

        // Registration-time probe: whether the resilience handler participates in the pipeline
        // must be decided while building the IHttpClientBuilder, before any IServiceProvider
        // exists. Options are populated exclusively by the configure delegate (Action pattern,
        // no IConfiguration binding), so applying it to a scratch instance yields the same
        // EnableResilience value the runtime options will carry. See the XML docs on
        // VaultOptions.EnableResilience for the (documented) limitation this implies.
        VaultOptions probe = new();
        configure(probe);

        // SINGLETON on purpose: the token cache (AppRole) must be shared across the transient
        // typed clients handed out by the factory. TryAdd lets consumers plug their own
        // IVaultTokenProvider (e.g. Kubernetes auth) before calling AddVaultProvider.
        services.TryAddSingleton<IVaultTokenProvider>(CreateTokenProvider);

        IHttpClientBuilder httpClientBuilder = services.AddHttpClient<VaultKeyEncryptionProvider>(
            (sp, client) => ConfigureVaultHttpClient(sp, client, warnOnInsecureHttp: true));

        // H-B: the default IHttpClientFactory logging handlers would otherwise log the
        // X-Vault-Token value verbatim at Trace level. Redaction matches by header NAME, so it
        // covers the per-request header stamped by VaultAuthenticationHandler.
        httpClientBuilder.RedactLoggedHeaders([VaultHttpDefaults.TokenHeaderName]);

        // Pipeline order is deliberate: additional handlers run outermost-first in registration
        // order, so adding the resilience handler BEFORE the auth handler places resilience
        // OUTSIDE auth. Every retry attempt then re-enters the auth handler and gets a
        // fresh-token opportunity. (The standard retry policy does not retry 403s, so it never
        // interferes with the auth handler's own single 403 retry.)
        if (probe.EnableResilience)
        {
            AddVaultResilience(httpClientBuilder);
        }

        httpClientBuilder.AddHttpMessageHandler(
            sp => new VaultAuthenticationHandler(sp.GetRequiredService<IVaultTokenProvider>()));

        // Dedicated AppRole login client: same base address / timeout / buffering rules, but
        // WITHOUT the auth handler (a login must not require a token — adding the handler would
        // recurse through the token provider). Registered unconditionally; it is only ever
        // constructed when AppRoleVaultTokenProvider actually logs in. The insecure-http warning
        // is emitted by the typed client only, to avoid duplicate warnings per construction.
        IHttpClientBuilder loginClientBuilder = services.AddHttpClient(
            VaultHttpDefaults.AppRoleLoginClientName,
            (sp, client) => ConfigureVaultHttpClient(sp, client, warnOnInsecureHttp: false));
        loginClientBuilder.RedactLoggedHeaders([VaultHttpDefaults.TokenHeaderName]);
        if (probe.EnableResilience)
        {
            // AppRole login POSTs are safe to retry: each login simply mints a token, and a
            // duplicate token from a retried attempt is harmless.
            AddVaultResilience(loginClientBuilder);
        }

        services.TryAddTransient<IKeyEncryptionProvider>(sp => sp.GetRequiredService<VaultKeyEncryptionProvider>());

        return services;
    }

    private static IVaultTokenProvider CreateTokenProvider(IServiceProvider serviceProvider)
    {
        IOptions<VaultOptions> options = serviceProvider.GetRequiredService<IOptions<VaultOptions>>();
        return options.Value.AuthMethod switch
        {
            VaultAuthMethod.AppRole => new AppRoleVaultTokenProvider(
                serviceProvider.GetRequiredService<IHttpClientFactory>(),
                options,
                serviceProvider.GetService<TimeProvider>() ?? TimeProvider.System,
                serviceProvider.GetRequiredService<ILogger<AppRoleVaultTokenProvider>>()),
            _ => new StaticVaultTokenProvider(options),
        };
    }

    private static void ConfigureVaultHttpClient(IServiceProvider serviceProvider, HttpClient client, bool warnOnInsecureHttp)
    {
        VaultOptions opts = serviceProvider.GetRequiredService<IOptions<VaultOptions>>().Value;

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
        if (warnOnInsecureHttp && baseAddress.Scheme == Uri.UriSchemeHttp)
        {
            ILogger<VaultKeyEncryptionProvider> logger =
                serviceProvider.GetRequiredService<ILogger<VaultKeyEncryptionProvider>>();
            LogInsecureHttpEnabled(logger, baseAddress.Host);
        }

        client.BaseAddress = baseAddress;

        // When the resilience handler is active, it owns the deadlines (per-attempt timeout =
        // HttpTimeout, overall TotalRequestTimeout budgets all attempts plus backoff). The
        // HttpClient.Timeout would otherwise cut retries short, so it is set to infinite —
        // the Microsoft-recommended pattern for the standard resilience handler. Without
        // resilience, HttpTimeout applies to the single attempt, as in Vellum 0.1.x.
        client.Timeout = opts.EnableResilience ? Timeout.InfiniteTimeSpan : opts.HttpTimeout;
        client.MaxResponseContentBufferSize = VaultHttpDefaults.MaxResponseContentBufferBytes;
    }

    private static void AddVaultResilience(IHttpClientBuilder httpClientBuilder)
    {
        // Conservative tuning of the standard handler: retries stay at the standard defaults
        // (3 attempts, exponential backoff with jitter, transient failures only: 5xx / 408 /
        // 429 / timeouts / connection errors — Vault Transit encrypt/decrypt and AppRole login
        // POSTs are all safe to retry). Timeouts and the circuit-breaker sampling window are
        // derived from the user's HttpTimeout so the pipeline passes the standard handler's
        // option validation for any supplied value — see VaultResilienceTimeouts.
        httpClientBuilder.AddStandardResilienceHandler().Configure(
            (HttpStandardResilienceOptions resilience, IServiceProvider sp) =>
            {
                VaultOptions opts = sp.GetRequiredService<IOptions<VaultOptions>>().Value;
                resilience.AttemptTimeout.Timeout = VaultResilienceTimeouts.AttemptTimeout(opts.HttpTimeout);
                resilience.TotalRequestTimeout.Timeout = VaultResilienceTimeouts.TotalRequestTimeout(opts.HttpTimeout);
                resilience.CircuitBreaker.SamplingDuration = VaultResilienceTimeouts.CircuitBreakerSamplingDuration(opts.HttpTimeout);
                resilience.Retry.MaxRetryAttempts = 3;
            });
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
