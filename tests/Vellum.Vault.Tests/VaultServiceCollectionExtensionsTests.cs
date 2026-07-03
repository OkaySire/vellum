using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Vellum.Vault.Tests.Fakes;
using Xunit;

namespace Vellum.Vault.Tests;

public sealed class VaultServiceCollectionExtensionsTests
{
    [Fact]
    public void AddVaultProvider_ValidOptions_RegistersIKeyEncryptionProvider()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "https://vault.example:8200";
            opts.Token = "hvs.abc";
            opts.KeyName = "my-kek";
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IKeyEncryptionProvider provider = sp.GetRequiredService<IKeyEncryptionProvider>();

        provider.Should().BeOfType<VaultKeyEncryptionProvider>();
        provider.ProviderName.Should().Be("vault");
    }

    [Fact]
    public void AddVaultProvider_ConfiguresHttpClient_WithBaseAddress_AndNoDefaultTokenHeader()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "https://vault.example:8200";
            opts.Token = "hvs.abc";
            opts.KeyName = "my-kek";
            opts.HttpTimeout = TimeSpan.FromSeconds(5);
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IHttpClientFactory factory = sp.GetRequiredService<IHttpClientFactory>();
        HttpClient httpClient = factory.CreateClient(nameof(VaultKeyEncryptionProvider));

        httpClient.BaseAddress.Should().Be(new Uri("https://vault.example:8200/"));
        // G1: the token moved from DefaultRequestHeaders to a per-request header stamped by
        // VaultAuthenticationHandler — a leaked/captured HttpClient no longer carries the secret.
        httpClient.DefaultRequestHeaders.Contains("X-Vault-Token").Should().BeFalse();
        // G2: with EnableResilience (the default), the resilience pipeline owns the deadline
        // (per-attempt timeout = HttpTimeout) and HttpClient.Timeout is set to infinite.
        // Timeout behavior for both EnableResilience values is pinned in VaultAuthResilienceDiTests.
        httpClient.Timeout.Should().Be(Timeout.InfiniteTimeSpan);
    }

    [Fact]
    public void AddVaultProvider_MissingAddress_ThrowsOnValidation()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "";
            opts.Token = "hvs.abc";
            opts.KeyName = "my-kek";
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IOptions<VaultOptions> options = sp.GetRequiredService<IOptions<VaultOptions>>();

        Action act = () => _ = options.Value;

        act.Should().Throw<OptionsValidationException>()
            .Where(ex => ex.Failures.Any(f => f.Contains("Address", StringComparison.Ordinal)));
    }

    [Fact]
    public void AddVaultProvider_MissingToken_ThrowsOnValidation()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "https://vault.example:8200";
            opts.Token = "";
            opts.KeyName = "my-kek";
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IOptions<VaultOptions> options = sp.GetRequiredService<IOptions<VaultOptions>>();

        Action act = () => _ = options.Value;

        act.Should().Throw<OptionsValidationException>()
            .Where(ex => ex.Failures.Any(f => f.Contains("Token", StringComparison.Ordinal)
                                              && !f.Contains("hvs", StringComparison.Ordinal)));
    }

    [Fact]
    public void AddVaultProvider_MissingKeyName_ThrowsOnValidation()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "https://vault.example:8200";
            opts.Token = "hvs.abc";
            opts.KeyName = "";
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IOptions<VaultOptions> options = sp.GetRequiredService<IOptions<VaultOptions>>();

        Action act = () => _ = options.Value;

        act.Should().Throw<OptionsValidationException>()
            .Where(ex => ex.Failures.Any(f => f.Contains("KeyName", StringComparison.Ordinal)));
    }

    [Fact]
    public void AddVaultProvider_InvalidAddressWithUserInfo_DoesNotLeakCredentials()
    {
        // L-2: if a malformed Address contains a `user:pass@` userinfo prefix, the
        // validation error must NOT echo the credential. The scrub strips the userinfo
        // before embedding the Address in the failure message.
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(opts =>
        {
            // Invalid scheme so we hit the echoing branch of the validator.
            opts.Address = "ftp://alice:supersecret@vault.example:8200";
            opts.Token = "hvs.abc";
            opts.KeyName = "my-kek";
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IOptions<VaultOptions> options = sp.GetRequiredService<IOptions<VaultOptions>>();

        Action act = () => _ = options.Value;

        OptionsValidationException ex = act.Should().Throw<OptionsValidationException>().Which;
        foreach (string failure in ex.Failures)
        {
            failure.Should().NotContain("alice",
                "userinfo username must never appear in a validation failure message");
            failure.Should().NotContain("supersecret",
                "userinfo password must never appear in a validation failure message");
            failure.Should().NotContain("alice:supersecret",
                "the raw userinfo block must be scrubbed out before echoing");
        }
    }

    [Fact]
    public void AddVaultProvider_InvalidAddressScheme_ThrowsOnValidation()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "ftp://vault.example:8200";
            opts.Token = "hvs.abc";
            opts.KeyName = "my-kek";
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IOptions<VaultOptions> options = sp.GetRequiredService<IOptions<VaultOptions>>();

        Action act = () => _ = options.Value;

        act.Should().Throw<OptionsValidationException>()
            .Where(ex => ex.Failures.Any(f => f.Contains("http://", StringComparison.Ordinal)
                                              || f.Contains("https://", StringComparison.Ordinal)));
    }

    [Fact]
    public void AddVaultProvider_ValidateOnStart_FailsAtHostStartup()
    {
        // Verify that ValidateOnStart wires the validation to IStartupValidator so that the
        // host fails fast before any wrap/unwrap call is ever issued.
        ServiceCollection services = new();
        services.AddLogging();
        services.AddOptions();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "";
            opts.Token = "";
            opts.KeyName = "";
        });

        using ServiceProvider sp = services.BuildServiceProvider();

        // The IStartupValidator is only registered when ValidateOnStart() is active.
        object? startupValidator = sp.GetService(
            typeof(Microsoft.Extensions.Options.IStartupValidator));
        startupValidator.Should().NotBeNull("because ValidateOnStart should register IStartupValidator");

        Action act = () => ((Microsoft.Extensions.Options.IStartupValidator)startupValidator!).Validate();
        act.Should().Throw<OptionsValidationException>();
    }

    [Fact]
    public void AddVaultProvider_DoesNotOverrideExistingIKeyEncryptionProvider()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<IKeyEncryptionProvider, NoopProvider>();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "https://vault.example:8200";
            opts.Token = "hvs.abc";
            opts.KeyName = "my-kek";
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IKeyEncryptionProvider provider = sp.GetRequiredService<IKeyEncryptionProvider>();

        provider.Should().BeOfType<NoopProvider>("because TryAddTransient must not override an earlier explicit registration");
    }

    [Fact]
    public void AddVaultProvider_HttpAddressWithoutAllowInsecureHttp_ThrowsOnValidation()
    {
        // H-A: plain http:// transmits the Vault token and plaintext DEKs in cleartext, so it
        // must fail closed unless the consumer explicitly opts in.
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "http://vault.example:8200";
            opts.Token = "hvs.abc";
            opts.KeyName = "my-kek";
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IOptions<VaultOptions> options = sp.GetRequiredService<IOptions<VaultOptions>>();

        Action act = () => _ = options.Value;

        act.Should().Throw<OptionsValidationException>()
            .Where(ex => ex.Failures.Any(f => f.Contains("AllowInsecureHttp", StringComparison.Ordinal)
                                              && f.Contains("cleartext", StringComparison.Ordinal)));
    }

    [Fact]
    public void AddVaultProvider_HttpAddressWithAllowInsecureHttp_ResolvesProvider()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "http://127.0.0.1:8200";
            opts.Token = "hvs.dev";
            opts.KeyName = "my-kek";
            opts.AllowInsecureHttp = true;
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IKeyEncryptionProvider provider = sp.GetRequiredService<IKeyEncryptionProvider>();

        provider.Should().BeOfType<VaultKeyEncryptionProvider>();
    }

    [Fact]
    public void AddVaultProvider_HttpsAddressWithoutAllowInsecureHttp_PassesValidation()
    {
        // https never requires the opt-in flag.
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "https://vault.example:8200";
            opts.Token = "hvs.abc";
            opts.KeyName = "my-kek";
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IOptions<VaultOptions> options = sp.GetRequiredService<IOptions<VaultOptions>>();

        Action act = () => _ = options.Value;

        act.Should().NotThrow();
        options.Value.AllowInsecureHttp.Should().BeFalse();
    }

    [Fact]
    public void AddVaultProvider_HttpAddressWithoutAllowInsecureHttp_FailsAtStartupValidation()
    {
        // L20 pattern: ValidateOnStart() registers IStartupValidator — exactly what the host
        // invokes at start-up — so we can assert fail-fast behaviour without a Host.
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "http://vault.example:8200";
            opts.Token = "hvs.abc";
            opts.KeyName = "my-kek";
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IStartupValidator startupValidator = sp.GetRequiredService<IStartupValidator>();

        // Since G2, ValidateOnStart() covers several options pipelines (VaultOptions plus the
        // two standard-resilience pipelines whose Configure reads VaultOptions), so the startup
        // validator aggregates one OptionsValidationException per pipeline — all carrying the
        // same VaultOptions failure. Unwrap rather than assume a single exception.
        Exception? caught = null;
        try
        {
            startupValidator.Validate();
        }
        catch (AggregateException ex)
        {
            caught = ex;
        }
        catch (OptionsValidationException ex)
        {
            caught = ex;
        }

        caught.Should().NotBeNull("start-up validation must fail fast on a plain http:// address");
        OptionsValidationException[] validationFailures = caught switch
        {
            AggregateException aggregate => aggregate.InnerExceptions.OfType<OptionsValidationException>().ToArray(),
            OptionsValidationException single => [single],
            _ => [],
        };
        validationFailures.Should().NotBeEmpty();
        validationFailures.SelectMany(ex => ex.Failures)
            .Should().Contain(f => f.Contains("AllowInsecureHttp", StringComparison.Ordinal));
    }

    [Fact]
    public void AddVaultProvider_InsecureHttpEnabled_LogsWarningWithoutToken()
    {
        // H-A: opting into plain http must produce a loud Warning when the Vault HttpClient is
        // constructed — and the warning must never include the token value.
        ServiceCollection services = new();
        services.AddLogging();
        CapturingLogger<VaultKeyEncryptionProvider> capturingLogger = new();
        services.AddSingleton<ILogger<VaultKeyEncryptionProvider>>(capturingLogger);
        services.AddVaultProvider(opts =>
        {
            opts.Address = "http://127.0.0.1:8200";
            opts.Token = "hvs.supersecret";
            opts.KeyName = "my-kek";
            opts.AllowInsecureHttp = true;
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IHttpClientFactory factory = sp.GetRequiredService<IHttpClientFactory>();
        _ = factory.CreateClient(nameof(VaultKeyEncryptionProvider));

        CapturedLogEntry warning = capturingLogger.Entries
            .Should().ContainSingle(e => e.Level == LogLevel.Warning).Which;
        warning.Message.Should().Contain("http://", "the warning must spell out the insecure scheme");
        warning.Message.Should().Contain("127.0.0.1", "the warning identifies the insecure host");
        warning.Message.Should().NotContain("hvs.supersecret", "the token must never be logged");
    }

    [Fact]
    public void AddVaultProvider_HttpsAddress_DoesNotLogInsecureWarning()
    {
        ServiceCollection services = new();
        services.AddLogging();
        CapturingLogger<VaultKeyEncryptionProvider> capturingLogger = new();
        services.AddSingleton<ILogger<VaultKeyEncryptionProvider>>(capturingLogger);
        services.AddVaultProvider(opts =>
        {
            opts.Address = "https://vault.example:8200";
            opts.Token = "hvs.abc";
            opts.KeyName = "my-kek";
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IHttpClientFactory factory = sp.GetRequiredService<IHttpClientFactory>();
        _ = factory.CreateClient(nameof(VaultKeyEncryptionProvider));

        capturingLogger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning);
    }

    [Fact]
    public void AddVaultProvider_RedactsVaultTokenHeader_InHttpClientFactoryLogs()
    {
        // H-B: the default IHttpClientFactory logging handlers log all request headers at Trace
        // level. RedactLoggedHeaders wires HttpClientFactoryOptions.ShouldRedactHeaderValue so
        // the X-Vault-Token value is replaced before it ever reaches a log sink.
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "https://vault.example:8200";
            opts.Token = "hvs.abc";
            opts.KeyName = "my-kek";
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IOptionsMonitor<HttpClientFactoryOptions> monitor =
            sp.GetRequiredService<IOptionsMonitor<HttpClientFactoryOptions>>();
        HttpClientFactoryOptions factoryOptions = monitor.Get(nameof(VaultKeyEncryptionProvider));

        factoryOptions.ShouldRedactHeaderValue("X-Vault-Token")
            .Should().BeTrue("the Vault token header must be redacted from HttpClientFactory logs");
        factoryOptions.ShouldRedactHeaderValue("x-vault-token")
            .Should().BeTrue("header-name matching must be case-insensitive");
        factoryOptions.ShouldRedactHeaderValue("Accept")
            .Should().BeFalse("only the token header is sensitive");
    }

    [Fact]
    public void AddVaultProvider_CapsMaxResponseContentBufferSize_At64KiB()
    {
        // M-E: a malicious Vault returning a multi-gigabyte error body must hit the buffering
        // cap (HttpRequestException, fail closed) instead of forcing unbounded allocations.
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(opts =>
        {
            opts.Address = "https://vault.example:8200";
            opts.Token = "hvs.abc";
            opts.KeyName = "my-kek";
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IHttpClientFactory factory = sp.GetRequiredService<IHttpClientFactory>();
        HttpClient httpClient = factory.CreateClient(nameof(VaultKeyEncryptionProvider));

        httpClient.MaxResponseContentBufferSize.Should().Be(64 * 1024);
    }

    private sealed class NoopProvider : IKeyEncryptionProvider
    {
        public string ProviderName => "noop";
        public Task<WrappedKey> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WrappedKey("x", "v1"));
        public Task<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default) =>
            Task.FromResult(Array.Empty<byte>());

        public Task<WrappedKey> RewrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WrappedKey("x", "v1"));
    }
}
