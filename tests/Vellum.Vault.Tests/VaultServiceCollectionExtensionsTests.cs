using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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
    public void AddVaultProvider_ConfiguresHttpClient_WithBaseAddressAndToken()
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
        httpClient.Timeout.Should().Be(TimeSpan.FromSeconds(5));
        httpClient.DefaultRequestHeaders.GetValues("X-Vault-Token").Should().ContainSingle().Which.Should().Be("hvs.abc");
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

    private sealed class NoopProvider : IKeyEncryptionProvider
    {
        public string ProviderName => "noop";
        public Task<WrappedKey> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WrappedKey("x", "v1"));
        public Task<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default) =>
            Task.FromResult(Array.Empty<byte>());
    }
}
