using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace Vellum.Static.Tests;

public sealed class StaticServiceCollectionExtensionsTests
{
    private static string ValidBase64Key() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static ServiceProvider BuildProvider(Action<StaticOptions> configure)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddStaticProvider(configure);
        return services.BuildServiceProvider();
    }

    [Fact]
    public void AddStaticProvider_NullServices_Throws()
    {
        IServiceCollection services = null!;

        Action act = () => services.AddStaticProvider(_ => { });

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddStaticProvider_NullConfigure_Throws()
    {
        ServiceCollection services = new();

        Action act = () => services.AddStaticProvider(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddStaticProvider_RegistersIKeyEncryptionProvider()
    {
        string key = ValidBase64Key();

        using ServiceProvider sp = BuildProvider(options => options.Base64Key = key);

        IKeyEncryptionProvider resolved = sp.GetRequiredService<IKeyEncryptionProvider>();
        resolved.Should().BeOfType<StaticKeyEncryptionProvider>();
        resolved.ProviderName.Should().Be("static");
    }

    [Fact]
    public void AddStaticProvider_IKeyEncryptionProviderAndConcreteType_AreSameSingletonInstance()
    {
        string key = ValidBase64Key();

        using ServiceProvider sp = BuildProvider(options => options.Base64Key = key);

        IKeyEncryptionProvider asInterface = sp.GetRequiredService<IKeyEncryptionProvider>();
        StaticKeyEncryptionProvider asConcrete = sp.GetRequiredService<StaticKeyEncryptionProvider>();

        asInterface.Should().BeSameAs(asConcrete);
    }

    [Fact]
    public void AddStaticProvider_DoesNotOverrideExistingIKeyEncryptionProvider()
    {
        ServiceCollection services = new();
        services.AddLogging();
        NoopProvider existing = new();
        services.AddSingleton<IKeyEncryptionProvider>(existing);

        services.AddStaticProvider(options => options.Base64Key = ValidBase64Key());

        using ServiceProvider sp = services.BuildServiceProvider();

        sp.GetRequiredService<IKeyEncryptionProvider>().Should().BeSameAs(existing);
    }

    [Fact]
    public void AddStaticProvider_MissingKey_FailsValidation()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddStaticProvider(options => options.Base64Key = string.Empty);

        using ServiceProvider sp = services.BuildServiceProvider();

        Action act = () => _ = sp.GetRequiredService<IOptions<StaticOptions>>().Value;

        act.Should().Throw<OptionsValidationException>()
            .WithMessage("*must be a non-empty base64-encoded 32-byte AES-256 key*");
    }

    [Fact]
    public void AddStaticProvider_InvalidBase64_FailsValidation()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddStaticProvider(options => options.Base64Key = "not-base64!!!");

        using ServiceProvider sp = services.BuildServiceProvider();

        Action act = () => _ = sp.GetRequiredService<IOptions<StaticOptions>>().Value;

        act.Should().Throw<OptionsValidationException>()
            .WithMessage("*not valid base64*");
    }

    [Fact]
    public void AddStaticProvider_WrongKeySize_FailsValidation()
    {
        string sixteenBytes = Convert.ToBase64String(new byte[16]);
        ServiceCollection services = new();
        services.AddLogging();
        services.AddStaticProvider(options => options.Base64Key = sixteenBytes);

        using ServiceProvider sp = services.BuildServiceProvider();

        Action act = () => _ = sp.GetRequiredService<IOptions<StaticOptions>>().Value;

        act.Should().Throw<OptionsValidationException>()
            .WithMessage("*must decode to exactly 32 bytes*got 16*");
    }

    [Fact]
    public void AddStaticProvider_ValidationFailureMessage_NeverIncludesKeyValue()
    {
        const string secretButInvalidBase64 = "this-should-not-leak-into-error-messages-!@#";
        ServiceCollection services = new();
        services.AddLogging();
        services.AddStaticProvider(options => options.Base64Key = secretButInvalidBase64);

        using ServiceProvider sp = services.BuildServiceProvider();

        try
        {
            _ = sp.GetRequiredService<IOptions<StaticOptions>>().Value;
            Assert.Fail("Expected OptionsValidationException.");
        }
        catch (OptionsValidationException ex)
        {
            ex.Message.Should().NotContain(secretButInvalidBase64);
        }
    }

    [Fact]
    public void AddStaticProvider_ValidateOnStart_RegistersStartupValidator()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddStaticProvider(options => options.Base64Key = string.Empty);

        using ServiceProvider sp = services.BuildServiceProvider();

        // ValidateOnStart() wires up IStartupValidator — resolving and invoking it must reject
        // the empty key identically to the eager Options resolution path.
        IStartupValidator validator = sp.GetRequiredService<IStartupValidator>();

        Action act = validator.Validate;

        act.Should().Throw<OptionsValidationException>();
    }

    [Fact]
    public void AddStaticProvider_ConfigureDelegateIsInvoked_OnOptionsResolution()
    {
        string expected = ValidBase64Key();
        using ServiceProvider sp = BuildProvider(options => options.Base64Key = expected);

        StaticOptions resolved = sp.GetRequiredService<IOptions<StaticOptions>>().Value;

        resolved.Base64Key.Should().Be(expected);
    }

    private sealed class NoopProvider : IKeyEncryptionProvider
    {
        public string ProviderName => "noop";

        public Task<WrappedKey> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WrappedKey("noop", "v1"));

        public Task<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default) =>
            Task.FromResult(Array.Empty<byte>());
    }
}
