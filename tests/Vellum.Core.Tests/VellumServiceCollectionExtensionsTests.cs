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

        // M-C: the DEK cache is a Vellum-owned singleton...
        scope.ServiceProvider.GetRequiredService<VellumDekCache>().Should().NotBeNull();
        provider.GetRequiredService<VellumDekCache>().Should().BeSameAs(
            scope.ServiceProvider.GetRequiredService<VellumDekCache>(),
            "the DEK cache must be a singleton so DEKs survive across DI scopes");

        // ...and AddVellum must NOT register the application-wide IMemoryCache anymore.
        provider.GetService<IMemoryCache>().Should().BeNull(
            "AddVellum must not register (nor depend on) the shared application cache");
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
    public async Task AddVellum_DoesNotTouchApplicationMemoryCache()
    {
        // M-C: plaintext DEKs must never land in the application's shared IMemoryCache —
        // any in-process code resolving IMemoryCache could read them under the deterministic
        // "vellum:" keys. Register a consumer-owned app cache alongside Vellum, encrypt, and
        // prove the app cache stayed empty.
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<IKeyEncryptionProvider, FakeKeyEncryptionProvider>();
        services.AddSingleton<IEncryptionKeyStore, FakeEncryptionKeyStore>();
        services.AddMemoryCache(); // consumer-owned application cache
        services.AddVellum();

        using ServiceProvider provider = services.BuildServiceProvider();
        using IServiceScope scope = provider.CreateScope();

        IDekManager dekManager = scope.ServiceProvider.GetRequiredService<IDekManager>();
        Dek dek = await dekManager.GetActiveDekAsync("tenant:42");
        dek.Key.Should().HaveCount(32);

        MemoryCache appCache = (MemoryCache)provider.GetRequiredService<IMemoryCache>();
        appCache.Count.Should().Be(0, "plaintext DEKs must live only in the Vellum-owned cache");
        appCache.TryGetValue("vellum:dek:active:tenant:42", out object? _).Should().BeFalse();
        appCache.TryGetValue($"vellum:dek:id:tenant:42:{dek.KeyId}", out object? _).Should().BeFalse();
    }

    [Fact]
    public async Task AddVellum_WithSizeLimitedApplicationCache_EncryptionUnaffected()
    {
        // L25 regression under the new topology: a consumer-configured IMemoryCache with
        // SizeLimit used to crash every cache write (entries without Size). Now the DEK
        // cache is Vellum-owned, so the consumer's SizeLimit must be entirely irrelevant.
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<IKeyEncryptionProvider, FakeKeyEncryptionProvider>();
        services.AddSingleton<IEncryptionKeyStore, FakeEncryptionKeyStore>();
        services.AddMemoryCache(options => options.SizeLimit = 1);
        services.AddVellum();

        using ServiceProvider provider = services.BuildServiceProvider();
        using IServiceScope scope = provider.CreateScope();

        IPayloadEncryptor encryptor = scope.ServiceProvider.GetRequiredService<IPayloadEncryptor>();
        byte[] plaintext = [1, 2, 3, 4, 5];

        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, "tenant:42");
        byte[] roundtrip = await encryptor.DecryptAsync(envelope, "tenant:42");

        roundtrip.Should().Equal(plaintext);
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
