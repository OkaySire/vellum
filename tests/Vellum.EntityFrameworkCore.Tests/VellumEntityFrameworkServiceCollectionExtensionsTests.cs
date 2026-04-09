using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Vellum.EntityFrameworkCore;
using Vellum.EntityFrameworkCore.Internal;
using Vellum.EntityFrameworkCore.Tests.Fixtures;
using Xunit;

namespace Vellum.EntityFrameworkCore.Tests;

public sealed class VellumEntityFrameworkServiceCollectionExtensionsTests
{
    [Fact]
    public void AddEntityFrameworkCoreStore_NullServices_Throws()
    {
        Action act = () => ((IServiceCollection)null!).AddEntityFrameworkCoreStore<TestDbContext>();

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddEntityFrameworkCoreStore_RegistersScopedStore()
    {
        TestOptionsAccessor.Current = new VellumEntityFrameworkOptions
        {
            UniqueActiveIndexFilter = "\"IsActive\" = 1",
        };

        using SqliteConnection connection = new("DataSource=:memory:");
        connection.Open();

        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<TestDbContext>(options => options.UseSqlite(connection));
        services.AddEntityFrameworkCoreStore<TestDbContext>();

        ServiceDescriptor descriptor = services
            .Single(d => d.ServiceType == typeof(IEncryptionKeyStore));
        descriptor.Lifetime.Should().Be(ServiceLifetime.Scoped);
    }

    [Fact]
    public void AddEntityFrameworkCoreStore_ResolvesToEfCoreStore()
    {
        TestOptionsAccessor.Current = new VellumEntityFrameworkOptions
        {
            UniqueActiveIndexFilter = "\"IsActive\" = 1",
        };

        using SqliteConnection connection = new("DataSource=:memory:");
        connection.Open();

        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<TestDbContext>(options => options.UseSqlite(connection));
        services.AddEntityFrameworkCoreStore<TestDbContext>();

        using ServiceProvider provider = services.BuildServiceProvider();
        using IServiceScope scope = provider.CreateScope();

        IEncryptionKeyStore store = scope.ServiceProvider.GetRequiredService<IEncryptionKeyStore>();
        store.Should().BeOfType<EntityFrameworkCoreEncryptionKeyStore<TestDbContext>>();
    }

    [Fact]
    public void AddEntityFrameworkCoreStore_DoesNotOverrideExistingRegistration()
    {
        using SqliteConnection connection = new("DataSource=:memory:");
        connection.Open();

        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<TestDbContext>(options => options.UseSqlite(connection));
        services.AddSingleton<IEncryptionKeyStore, CustomStore>();
        services.AddEntityFrameworkCoreStore<TestDbContext>();

        using ServiceProvider provider = services.BuildServiceProvider();
        using IServiceScope scope = provider.CreateScope();

        IEncryptionKeyStore store = scope.ServiceProvider.GetRequiredService<IEncryptionKeyStore>();
        store.Should().BeOfType<CustomStore>();
    }

    [Fact]
    public void AddEntityFrameworkCoreStore_ConfigureDelegate_IsApplied()
    {
        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddEntityFrameworkCoreStore<TestDbContext>(opts =>
        {
            opts.TableName = "custom_vellum_keys";
            opts.SchemaName = "vellum";
            opts.UniqueActiveIndexFilter = "[IsActive] = 1";
            opts.ScopeMaxLength = 512;
        });

        using ServiceProvider provider = services.BuildServiceProvider();
        VellumEntityFrameworkOptions options = provider
            .GetRequiredService<IOptions<VellumEntityFrameworkOptions>>()
            .Value;

        options.TableName.Should().Be("custom_vellum_keys");
        options.SchemaName.Should().Be("vellum");
        options.UniqueActiveIndexFilter.Should().Be("[IsActive] = 1");
        options.ScopeMaxLength.Should().Be(512);
    }

    [Fact]
    public void VellumEntityFrameworkOptions_FilterOverride_AppliedToModel()
    {
        // Prove that the filter string passed through options ends up on the created index.
        // Uses a dedicated DbContext type (FilterOverrideTestDbContext) so the custom options
        // do not leak into the EF Core model cache shared by TestDbContext tests.
        FilterOverrideTestDbContext.VellumOptions = new VellumEntityFrameworkOptions
        {
            TableName = "custom_keys",
            UniqueActiveIndexFilter = "\"IsActive\" = 1",
            ScopeMaxLength = 128,
        };

        using SqliteConnection connection = new("DataSource=:memory:");
        connection.Open();

        DbContextOptions<FilterOverrideTestDbContext> dbOptions = new DbContextOptionsBuilder<FilterOverrideTestDbContext>()
            .UseSqlite(connection)
            .Options;
        using FilterOverrideTestDbContext context = new(dbOptions);

        Microsoft.EntityFrameworkCore.Metadata.IEntityType entity = context.Model
            .FindEntityType(typeof(EncryptionKeyRecord))!;

        entity.GetTableName().Should().Be("custom_keys");

        Microsoft.EntityFrameworkCore.Metadata.IProperty scopeProperty = entity
            .FindProperty(nameof(EncryptionKeyRecord.Scope))!;
        scopeProperty.GetMaxLength().Should().Be(128);

        Microsoft.EntityFrameworkCore.Metadata.IIndex uniqueIndex = entity
            .GetIndexes()
            .Single(index => index.IsUnique);
        uniqueIndex.GetFilter().Should().Be("\"IsActive\" = 1");
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Performance",
        "CA1812:Avoid uninstantiated internal classes",
        Justification = "Instantiated by the DI container via AddSingleton<IEncryptionKeyStore, CustomStore>().")]
    private sealed class CustomStore : IEncryptionKeyStore
    {
        public Task<EncryptionKey?> GetActiveAsync(string scope, CancellationToken cancellationToken = default)
            => Task.FromResult<EncryptionKey?>(null);

        public Task<EncryptionKey?> GetByIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default)
            => Task.FromResult<EncryptionKey?>(null);

        public Task<EncryptionKey> CreateAsync(EncryptionKey key, CancellationToken cancellationToken = default)
            => Task.FromResult(key);

        public Task DeactivateAllAsync(string scope, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task<IReadOnlyList<EncryptionKey>> GetHistoricalAsync(string scope, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<EncryptionKey>>(Array.Empty<EncryptionKey>());

        public Task<IReadOnlyList<string>> GetActiveScopesAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());
    }
}
