using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Vellum.Tests.Fakes;
using Xunit;

namespace Vellum.Tests;

public sealed class VellumServiceCollectionExtensionsTests
{
    [Fact]
    public void AddVellum_RegistersCoreServices()
    {
        ServiceCollection services = new();

        // Consumer responsibility: register a KEK provider, a key store, and logging.
        services.AddLogging();
        services.AddSingleton<IKeyEncryptionProvider, FakeKeyEncryptionProvider>();
        services.AddSingleton<IEncryptionKeyStore, FakeEncryptionKeyStore>();

        services.AddVellum();

        using ServiceProvider provider = services.BuildServiceProvider();
        using IServiceScope scope = provider.CreateScope();

        scope.ServiceProvider.GetRequiredService<IDekManager>().Should().BeOfType<DekManager>();
        scope.ServiceProvider.GetRequiredService<IPayloadEncryptor>().Should().BeOfType<PayloadEncryptor>();
        scope.ServiceProvider.GetRequiredService<IRandomBytesProvider>().Should().BeOfType<DefaultRandomBytesProvider>();
        scope.ServiceProvider.GetRequiredService<TimeProvider>().Should().Be(TimeProvider.System);
        scope.ServiceProvider.GetRequiredService<IMemoryCache>().Should().NotBeNull();
    }

    [Fact]
    public void AddVellum_AppliesOptionsDelegate()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<IKeyEncryptionProvider, FakeKeyEncryptionProvider>();
        services.AddSingleton<IEncryptionKeyStore, FakeEncryptionKeyStore>();

        services.AddVellum(options => options.DekCacheTtl = TimeSpan.FromSeconds(5));

        using ServiceProvider provider = services.BuildServiceProvider();
        VellumOptions resolved = provider.GetRequiredService<IOptions<VellumOptions>>().Value;

        resolved.DekCacheTtl.Should().Be(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void AddVellum_DoesNotOverrideConsumerRegistrations()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<IKeyEncryptionProvider, FakeKeyEncryptionProvider>();
        services.AddSingleton<IEncryptionKeyStore, FakeEncryptionKeyStore>();
        services.AddSingleton<IRandomBytesProvider, CountingRandomBytesProvider>();

        services.AddVellum();

        using ServiceProvider provider = services.BuildServiceProvider();
        IRandomBytesProvider resolved = provider.GetRequiredService<IRandomBytesProvider>();
        resolved.Should().BeOfType<CountingRandomBytesProvider>(
            "consumer registrations must take precedence because AddVellum uses TryAdd");
    }
}
