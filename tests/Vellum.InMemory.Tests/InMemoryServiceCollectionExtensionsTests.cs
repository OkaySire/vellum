using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Vellum.InMemory;
using Xunit;

namespace Vellum.InMemory.Tests;

public sealed class InMemoryServiceCollectionExtensionsTests
{
    [Fact]
    public void AddInMemoryStore_NullServices_Throws()
    {
        IServiceCollection services = null!;

        Action act = () => services.AddInMemoryStore();

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddInMemoryStore_RegistersIEncryptionKeyStore()
    {
        ServiceCollection services = new();
        services.AddInMemoryStore();

        using ServiceProvider sp = services.BuildServiceProvider();
        IEncryptionKeyStore store = sp.GetRequiredService<IEncryptionKeyStore>();

        store.Should().BeOfType<InMemoryEncryptionKeyStore>();
    }

    [Fact]
    public void AddInMemoryStore_RegistersSingletonLifetime_SharedAcrossScopes()
    {
        // Two resolutions in different scopes must see the same instance — that is the whole
        // point of an in-memory store shared across DI scopes.
        ServiceCollection services = new();
        services.AddInMemoryStore();
        using ServiceProvider sp = services.BuildServiceProvider();

        IEncryptionKeyStore first;
        IEncryptionKeyStore second;
        using (IServiceScope scope1 = sp.CreateScope())
        {
            first = scope1.ServiceProvider.GetRequiredService<IEncryptionKeyStore>();
        }
        using (IServiceScope scope2 = sp.CreateScope())
        {
            second = scope2.ServiceProvider.GetRequiredService<IEncryptionKeyStore>();
        }

        first.Should().BeSameAs(second);
    }

    [Fact]
    public void AddInMemoryStore_BridgeResolvesSameInstanceAsConcreteType()
    {
        ServiceCollection services = new();
        services.AddInMemoryStore();
        using ServiceProvider sp = services.BuildServiceProvider();

        InMemoryEncryptionKeyStore concrete = sp.GetRequiredService<InMemoryEncryptionKeyStore>();
        IEncryptionKeyStore bridged = sp.GetRequiredService<IEncryptionKeyStore>();

        bridged.Should().BeSameAs(concrete);
    }

    [Fact]
    public void AddInMemoryStore_DoesNotOverrideExistingRegistration()
    {
        // TryAdd semantics: if the consumer registered their own IEncryptionKeyStore first,
        // AddInMemoryStore must not replace it.
        ServiceCollection services = new();
        CustomEncryptionKeyStore custom = new();
        services.AddSingleton<IEncryptionKeyStore>(custom);

        services.AddInMemoryStore();

        using ServiceProvider sp = services.BuildServiceProvider();
        IEncryptionKeyStore resolved = sp.GetRequiredService<IEncryptionKeyStore>();

        resolved.Should().BeSameAs(custom);
    }

    [Fact]
    public async Task AddInMemoryStore_ResolvedStore_IsFunctional()
    {
        // End-to-end: registering the store and resolving it yields a working store.
        ServiceCollection services = new();
        services.AddInMemoryStore();
        using ServiceProvider sp = services.BuildServiceProvider();
        IEncryptionKeyStore store = sp.GetRequiredService<IEncryptionKeyStore>();

        EncryptionKey key = new(
            KeyId: Guid.NewGuid(),
            Scope: "tenant:resolved",
            WrappedKey: new WrappedKey("ct", "v1"),
            CreatedAt: DateTimeOffset.UtcNow,
            ExpiresAt: null,
            IsActive: true);

        await store.CreateAsync(key);
        EncryptionKey? active = await store.GetActiveAsync("tenant:resolved");

        active.Should().NotBeNull();
        active!.KeyId.Should().Be(key.KeyId);
    }

    private sealed class CustomEncryptionKeyStore : IEncryptionKeyStore
    {
        public Task<EncryptionKey?> GetActiveAsync(string scope, CancellationToken cancellationToken = default)
            => Task.FromResult<EncryptionKey?>(null);

        public Task<EncryptionKey?> GetByIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default)
            => Task.FromResult<EncryptionKey?>(null);

        public Task<EncryptionKey> CreateAsync(EncryptionKey key, CancellationToken cancellationToken = default)
            => Task.FromResult(key);

        public Task DeactivateAllAsync(string scope, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task<EncryptionKey> RotateAsync(EncryptionKey newKey, CancellationToken cancellationToken = default)
            => Task.FromResult(newKey);

        public Task<IReadOnlyList<EncryptionKey>> GetHistoricalAsync(string scope, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<EncryptionKey>>(Array.Empty<EncryptionKey>());

        public Task<IReadOnlyList<string>> GetActiveScopesAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());
    }
}
