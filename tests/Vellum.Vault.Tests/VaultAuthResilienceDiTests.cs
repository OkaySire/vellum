using System.Globalization;
using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;
using Polly;
using Vellum.Vault.Tests.Fakes;
using Xunit;

namespace Vellum.Vault.Tests;

/// <summary>
/// DI wiring and end-to-end pipeline tests for G1 (token provider + auth handler) and
/// G2 (standard resilience handler). End-to-end tests run through the real
/// <see cref="IHttpClientFactory"/> pipeline with the primary (transport) handler replaced
/// by a fake, so the resilience handler, the auth handler, and their ordering are all
/// exercised for real.
/// </summary>
public sealed class VaultAuthResilienceDiTests
{
    private const string _tokenHeader = "X-Vault-Token";
    private const string _resilienceOptionsName = "VaultKeyEncryptionProvider-standard";

    private static void ConfigureToken(VaultOptions opts)
    {
        opts.Address = "https://vault.test:8200";
        opts.Token = "hvs.abc";
        opts.KeyName = "my-kek";
    }

    private static void ConfigureAppRole(VaultOptions opts)
    {
        opts.Address = "https://vault.test:8200";
        opts.KeyName = "my-kek";
        opts.AuthMethod = VaultAuthMethod.AppRole;
        opts.RoleId = "role-123";
        opts.SecretId = "secret-456";
    }

    private static ServiceProvider BuildProvider(
        Action<VaultOptions> configure,
        FakeHttpMessageHandler? primaryHandler = null,
        Action<IServiceCollection>? postConfigure = null)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(configure);

        if (primaryHandler is not null)
        {
            // Swap the transport for the fake on EVERY factory client (typed Transit client and
            // the AppRole login client) while keeping the full additional-handler pipeline —
            // resilience and auth handlers run exactly as in production.
            services.ConfigureAll<HttpClientFactoryOptions>(factoryOptions =>
                factoryOptions.HttpMessageHandlerBuilderActions.Add(builder => builder.PrimaryHandler = primaryHandler));
        }

        postConfigure?.Invoke(services);
        return services.BuildServiceProvider();
    }

    private static HttpResponseMessage Json(string json) =>
        new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static string TokenOf(HttpRequestMessage request) =>
        request.Headers.TryGetValues(_tokenHeader, out IEnumerable<string>? values) ? values.Single() : "";

    // ---------------------------------------------------------------------
    // Token provider registration
    // ---------------------------------------------------------------------

    [Fact]
    public void TokenAuthMethod_ResolvesStaticVaultTokenProvider()
    {
        using ServiceProvider sp = BuildProvider(ConfigureToken);

        IVaultTokenProvider tokenProvider = sp.GetRequiredService<IVaultTokenProvider>();

        tokenProvider.Should().BeOfType<StaticVaultTokenProvider>();
    }

    [Fact]
    public void AppRoleAuthMethod_ResolvesAppRoleVaultTokenProvider_AsSingleton()
    {
        using ServiceProvider sp = BuildProvider(ConfigureAppRole);

        IVaultTokenProvider first = sp.GetRequiredService<IVaultTokenProvider>();
        IVaultTokenProvider second = sp.GetRequiredService<IVaultTokenProvider>();

        first.Should().BeOfType<AppRoleVaultTokenProvider>();
        second.Should().BeSameAs(first, "the token cache must be shared across transient typed clients");
    }

    [Fact]
    public void CustomTokenProvider_RegisteredFirst_IsNotOverridden()
    {
        ServiceCollection services = new();
        services.AddLogging();
        FakeVaultTokenProvider custom = new("hvs.custom");
        services.AddSingleton<IVaultTokenProvider>(custom);
        services.AddVaultProvider(ConfigureToken);
        using ServiceProvider sp = services.BuildServiceProvider();

        sp.GetRequiredService<IVaultTokenProvider>().Should().BeSameAs(custom,
            "TryAddSingleton must respect an earlier explicit registration");
    }

    // ---------------------------------------------------------------------
    // HttpClient configuration (per-request auth, timeouts)
    // ---------------------------------------------------------------------

    [Fact]
    public void TypedClient_HasNoDefaultTokenHeader()
    {
        using ServiceProvider sp = BuildProvider(ConfigureToken);
        IHttpClientFactory factory = sp.GetRequiredService<IHttpClientFactory>();

        HttpClient httpClient = factory.CreateClient(nameof(VaultKeyEncryptionProvider));

        // G1: the token moved to a per-request header stamped by VaultAuthenticationHandler.
        // A leaked/captured HttpClient must no longer carry the credential.
        httpClient.DefaultRequestHeaders.Contains(_tokenHeader).Should().BeFalse();
    }

    [Fact]
    public void ResilienceEnabled_ClientTimeout_IsInfinite_PipelineOwnsDeadline()
    {
        using ServiceProvider sp = BuildProvider(opts =>
        {
            ConfigureToken(opts);
            opts.HttpTimeout = TimeSpan.FromSeconds(5);
        });
        IHttpClientFactory factory = sp.GetRequiredService<IHttpClientFactory>();

        HttpClient httpClient = factory.CreateClient(nameof(VaultKeyEncryptionProvider));

        httpClient.Timeout.Should().Be(Timeout.InfiniteTimeSpan,
            "HttpClient.Timeout would otherwise cut resilience retries short");
    }

    [Fact]
    public void ResilienceDisabled_ClientTimeout_IsHttpTimeout()
    {
        using ServiceProvider sp = BuildProvider(opts =>
        {
            ConfigureToken(opts);
            opts.HttpTimeout = TimeSpan.FromSeconds(5);
            opts.EnableResilience = false;
        });
        IHttpClientFactory factory = sp.GetRequiredService<IHttpClientFactory>();

        HttpClient httpClient = factory.CreateClient(nameof(VaultKeyEncryptionProvider));

        httpClient.Timeout.Should().Be(TimeSpan.FromSeconds(5), "0.1.x behavior is preserved without resilience");
    }

    // ---------------------------------------------------------------------
    // Resilience handler presence and tuning
    // ---------------------------------------------------------------------

    [Fact]
    public void EnableResilience_TogglesResilienceHandler_InPipeline()
    {
        static int HandlerBuilderActionCount(bool enableResilience)
        {
            using ServiceProvider sp = BuildProvider(opts =>
            {
                ConfigureToken(opts);
                opts.EnableResilience = enableResilience;
            });
            IOptionsMonitor<HttpClientFactoryOptions> monitor =
                sp.GetRequiredService<IOptionsMonitor<HttpClientFactoryOptions>>();
            return monitor.Get(nameof(VaultKeyEncryptionProvider)).HttpMessageHandlerBuilderActions.Count;
        }

        int withResilience = HandlerBuilderActionCount(enableResilience: true);
        int withoutResilience = HandlerBuilderActionCount(enableResilience: false);

        withResilience.Should().BeGreaterThan(withoutResilience,
            "EnableResilience = true (the default) must add the standard resilience handler; false must not");
    }

    [Fact]
    public void ResilienceOptions_AreDerivedFromHttpTimeout()
    {
        using ServiceProvider sp = BuildProvider(opts =>
        {
            ConfigureToken(opts);
            opts.HttpTimeout = TimeSpan.FromSeconds(7);
        });
        IOptionsMonitor<HttpStandardResilienceOptions> monitor =
            sp.GetRequiredService<IOptionsMonitor<HttpStandardResilienceOptions>>();

        HttpStandardResilienceOptions resilience = monitor.Get(_resilienceOptionsName);

        resilience.AttemptTimeout.Timeout.Should().Be(TimeSpan.FromSeconds(7), "per-attempt = HttpTimeout");
        resilience.TotalRequestTimeout.Timeout.Should().Be(TimeSpan.FromSeconds(48), "4 attempts × 7s + 20s backoff allowance");
        resilience.CircuitBreaker.SamplingDuration.Should().Be(TimeSpan.FromSeconds(30), "2 × 7s is below the 30s floor");
        resilience.Retry.MaxRetryAttempts.Should().Be(3);
    }

    [Fact]
    public void ResilienceSamplingDuration_TracksLargeHttpTimeouts()
    {
        using ServiceProvider sp = BuildProvider(opts =>
        {
            ConfigureToken(opts);
            opts.HttpTimeout = TimeSpan.FromSeconds(60);
        });
        IOptionsMonitor<HttpStandardResilienceOptions> monitor =
            sp.GetRequiredService<IOptionsMonitor<HttpStandardResilienceOptions>>();

        HttpStandardResilienceOptions resilience = monitor.Get(_resilienceOptionsName);

        resilience.CircuitBreaker.SamplingDuration.Should().Be(TimeSpan.FromSeconds(120),
            "the standard handler validator requires SamplingDuration ≥ 2 × AttemptTimeout");
    }

    // ---------------------------------------------------------------------
    // End-to-end through the real factory pipeline
    // ---------------------------------------------------------------------

    [Fact]
    public async Task EndToEnd_StaticToken_WrapStampsPerRequestHeader()
    {
        List<string> seenTokens = [];
        FakeHttpMessageHandler primary = new((request, ct) =>
        {
            seenTokens.Add(TokenOf(request));
            return Task.FromResult(Json("{\"data\":{\"ciphertext\":\"vault:v1:abc==\"}}"));
        });
        using ServiceProvider sp = BuildProvider(ConfigureToken, primary);

        IKeyEncryptionProvider provider = sp.GetRequiredService<IKeyEncryptionProvider>();
        WrappedKey wrapped = await provider.WrapAsync(new byte[32]);

        wrapped.Ciphertext.Should().Be("vault:v1:abc==");
        seenTokens.Should().Equal("hvs.abc");
    }

    [Fact]
    public async Task EndToEnd_AppRole_WrapUsesLoginToken()
    {
        int loginCount = 0;
        List<string> encryptTokens = [];
        FakeHttpMessageHandler primary = new((request, ct) =>
        {
            string path = request.RequestUri!.AbsolutePath;
            if (path == "/v1/auth/approle/login")
            {
                loginCount++;
                string token = "hvs.login" + loginCount.ToString(CultureInfo.InvariantCulture);
                return Task.FromResult(Json(
                    $"{{\"auth\":{{\"client_token\":\"{token}\",\"lease_duration\":3600,\"renewable\":true}}}}"));
            }

            encryptTokens.Add(TokenOf(request));
            return Task.FromResult(Json("{\"data\":{\"ciphertext\":\"vault:v1:abc==\"}}"));
        });
        using ServiceProvider sp = BuildProvider(ConfigureAppRole, primary);

        IKeyEncryptionProvider provider = sp.GetRequiredService<IKeyEncryptionProvider>();
        WrappedKey wrapped = await provider.WrapAsync(new byte[32]);

        wrapped.Ciphertext.Should().Be("vault:v1:abc==");
        loginCount.Should().Be(1);
        encryptTokens.Should().Equal("hvs.login1");
    }

    [Fact]
    public async Task EndToEnd_AppRole_403_ReloginsOnceAndSucceeds()
    {
        int loginCount = 0;
        List<string> encryptTokens = [];
        FakeHttpMessageHandler primary = new((request, ct) =>
        {
            string path = request.RequestUri!.AbsolutePath;
            if (path == "/v1/auth/approle/login")
            {
                loginCount++;
                string token = "hvs.login" + loginCount.ToString(CultureInfo.InvariantCulture);
                return Task.FromResult(Json(
                    $"{{\"auth\":{{\"client_token\":\"{token}\",\"lease_duration\":3600,\"renewable\":true}}}}"));
            }

            string seen = TokenOf(request);
            encryptTokens.Add(seen);
            return seen == "hvs.login1"
                ? Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden))
                : Task.FromResult(Json("{\"data\":{\"ciphertext\":\"vault:v1:abc==\"}}"));
        });
        using ServiceProvider sp = BuildProvider(ConfigureAppRole, primary);

        IKeyEncryptionProvider provider = sp.GetRequiredService<IKeyEncryptionProvider>();
        WrappedKey wrapped = await provider.WrapAsync(new byte[32]);

        wrapped.Ciphertext.Should().Be("vault:v1:abc==", "an expired token must be replaced transparently");
        loginCount.Should().Be(2, "the 403 must invalidate the cached token and trigger one fresh login");
        encryptTokens.Should().Equal("hvs.login1", "hvs.login2");
    }

    [Fact]
    public async Task EndToEnd_StaticToken_403_SingleAttempt_FailsClosed()
    {
        int encryptAttempts = 0;
        FakeHttpMessageHandler primary = new((request, ct) =>
        {
            encryptAttempts++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                Content = new StringContent("{\"errors\":[\"permission denied\"]}", Encoding.UTF8, "application/json"),
            });
        });
        using ServiceProvider sp = BuildProvider(ConfigureToken, primary);

        IKeyEncryptionProvider provider = sp.GetRequiredService<IKeyEncryptionProvider>();
        Func<Task> act = async () => await provider.WrapAsync(new byte[32]);

        await act.Should().ThrowAsync<InvalidOperationException>();
        encryptAttempts.Should().Be(1,
            "a static token cannot be re-acquired and 403 is not transient — no retry from either handler");
    }

    [Fact]
    public async Task EndToEnd_Resilience_RetriesTransient503_EveryAttemptCarriesToken()
    {
        int attempts = 0;
        List<string> seenTokens = [];
        FakeHttpMessageHandler primary = new((request, ct) =>
        {
            attempts++;
            seenTokens.Add(TokenOf(request));
            return attempts == 1
                ? Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))
                : Task.FromResult(Json("{\"data\":{\"ciphertext\":\"vault:v1:abc==\"}}"));
        });
        using ServiceProvider sp = BuildProvider(
            ConfigureToken,
            primary,
            postConfigure: services =>
                // Speed the test up: shrink the retry backoff. Runs AFTER AddVaultProvider's
                // Configure for the same named options, so it wins for these properties.
                services.Configure<HttpStandardResilienceOptions>(_resilienceOptionsName, resilience =>
                {
                    resilience.Retry.Delay = TimeSpan.FromMilliseconds(1);
                    resilience.Retry.BackoffType = DelayBackoffType.Constant;
                    resilience.Retry.UseJitter = false;
                }));

        IKeyEncryptionProvider provider = sp.GetRequiredService<IKeyEncryptionProvider>();
        WrappedKey wrapped = await provider.WrapAsync(new byte[32]);

        wrapped.Ciphertext.Should().Be("vault:v1:abc==", "a transient 503 must be retried");
        attempts.Should().Be(2);
        // Pins the pipeline ordering (resilience OUTSIDE auth): each retry attempt re-enters
        // the auth handler, so every attempt carries the token header.
        seenTokens.Should().Equal("hvs.abc", "hvs.abc");
    }

    [Fact]
    public async Task EndToEnd_ResilienceDisabled_503_SingleAttempt_FailsClosed()
    {
        int attempts = 0;
        FakeHttpMessageHandler primary = new((request, ct) =>
        {
            attempts++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        });
        using ServiceProvider sp = BuildProvider(
            opts =>
            {
                ConfigureToken(opts);
                opts.EnableResilience = false;
            },
            primary);

        IKeyEncryptionProvider provider = sp.GetRequiredService<IKeyEncryptionProvider>();
        Func<Task> act = async () => await provider.WrapAsync(new byte[32]);

        await act.Should().ThrowAsync<InvalidOperationException>();
        attempts.Should().Be(1, "with EnableResilience = false there is exactly one attempt, as in 0.1.x");
    }
}
