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
        using SqliteConnection connection = new("DataSource=:memory:");
        connection.Open();

        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<TestDbContext>(options => options
            .UseSqlite(connection)
            .UseVellum(v => v.UniqueActiveIndexFilter = "\"IsActive\" = 1"));
        services.AddEntityFrameworkCoreStore<TestDbContext>();

        ServiceDescriptor descriptor = services
            .Single(d => d.ServiceType == typeof(IEncryptionKeyStore));
        descriptor.Lifetime.Should().Be(ServiceLifetime.Scoped);
    }

    [Fact]
    public void AddEntityFrameworkCoreStore_ResolvesToEfCoreStore()
    {
        using SqliteConnection connection = new("DataSource=:memory:");
        connection.Open();

        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<TestDbContext>(options => options
            .UseSqlite(connection)
            .UseVellum(v => v.UniqueActiveIndexFilter = "\"IsActive\" = 1"));
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
        services.AddDbContext<TestDbContext>(options => options
            .UseSqlite(connection)
            .UseVellum(v => v.UniqueActiveIndexFilter = "\"IsActive\" = 1"));
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
    public void UseVellum_AttachesOptionsViaDbContextOptionsExtension()
    {
        // Issue #9: options flow from UseVellum on the DbContextOptionsBuilder all the way
        // into AddVellumEncryptionKeys at model-build time — no second literal, no
        // hand-duplicated configuration.
        using SqliteConnection connection = new("DataSource=:memory:");
        connection.Open();

        DbContextOptions<FilterOverrideTestDbContext> dbOptions = new DbContextOptionsBuilder<FilterOverrideTestDbContext>()
            .UseSqlite(connection)
            .UseVellum(opts =>
            {
                opts.TableName = "custom_keys";
                opts.UniqueActiveIndexFilter = "\"IsActive\" = 1";
                opts.ScopeMaxLength = 128;
            })
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

    [Fact]
    public void AddVellumEncryptionKeys_DefaultColumnNames_MatchPascalCase()
    {
        // Pin the out-of-the-box column naming so the EF Core migration story stays stable
        // for existing consumers who have not opted into column-name overrides.
        using SqliteConnection connection = new("DataSource=:memory:");
        connection.Open();

        DbContextOptions<DefaultColumnsTestDbContext> dbOptions = new DbContextOptionsBuilder<DefaultColumnsTestDbContext>()
            .UseSqlite(connection)
            .UseVellum(opts => opts.UniqueActiveIndexFilter = "\"IsActive\" = 1")
            .Options;

        using DefaultColumnsTestDbContext context = new(dbOptions);
        Microsoft.EntityFrameworkCore.Metadata.IEntityType entity = context.Model
            .FindEntityType(typeof(EncryptionKeyRecord))!;

        Microsoft.EntityFrameworkCore.Metadata.StoreObjectIdentifier storeObject =
            Microsoft.EntityFrameworkCore.Metadata.StoreObjectIdentifier.Table(
                entity.GetTableName()!,
                entity.GetSchema());

        entity.FindProperty(nameof(EncryptionKeyRecord.KeyId))!
            .GetColumnName(storeObject).Should().Be("KeyId");
        entity.FindProperty(nameof(EncryptionKeyRecord.Scope))!
            .GetColumnName(storeObject).Should().Be("Scope");
        entity.FindProperty(nameof(EncryptionKeyRecord.WrappedCiphertext))!
            .GetColumnName(storeObject).Should().Be("WrappedCiphertext");
        entity.FindProperty(nameof(EncryptionKeyRecord.WrappedProviderVersion))!
            .GetColumnName(storeObject).Should().Be("WrappedProviderVersion");
        entity.FindProperty(nameof(EncryptionKeyRecord.CreatedAt))!
            .GetColumnName(storeObject).Should().Be("CreatedAt");
        entity.FindProperty(nameof(EncryptionKeyRecord.ExpiresAt))!
            .GetColumnName(storeObject).Should().Be("ExpiresAt");
        entity.FindProperty(nameof(EncryptionKeyRecord.IsActive))!
            .GetColumnName(storeObject).Should().Be("IsActive");
    }

    [Fact]
    public void AddVellumEncryptionKeys_SnakeCaseColumnOverrides_FlowIntoModel()
    {
        // Issue #8: consumers integrating with a snake_case schema can rename every column
        // via VellumEntityFrameworkOptions. Override all 7 column names, then prove every
        // mapped column reflects the override.
        using SqliteConnection connection = new("DataSource=:memory:");
        connection.Open();

        DbContextOptions<SnakeCaseTestDbContext> dbOptions = new DbContextOptionsBuilder<SnakeCaseTestDbContext>()
            .UseSqlite(connection)
            .UseVellum(opts =>
            {
                opts.TableName = "bus_encryption_keys";
                opts.KeyIdColumnName = "key_id";
                opts.ScopeColumnName = "scope";
                opts.WrappedCiphertextColumnName = "wrapped_ciphertext";
                opts.WrappedProviderVersionColumnName = "wrapped_provider_version";
                opts.CreatedAtColumnName = "created_at";
                opts.ExpiresAtColumnName = "expires_at";
                opts.IsActiveColumnName = "is_active";
                opts.UniqueActiveIndexFilter = "\"is_active\" = 1";
            })
            .Options;

        using SnakeCaseTestDbContext context = new(dbOptions);
        Microsoft.EntityFrameworkCore.Metadata.IEntityType entity = context.Model
            .FindEntityType(typeof(EncryptionKeyRecord))!;

        entity.GetTableName().Should().Be("bus_encryption_keys");

        Microsoft.EntityFrameworkCore.Metadata.StoreObjectIdentifier storeObject =
            Microsoft.EntityFrameworkCore.Metadata.StoreObjectIdentifier.Table(
                entity.GetTableName()!,
                entity.GetSchema());

        entity.FindProperty(nameof(EncryptionKeyRecord.KeyId))!
            .GetColumnName(storeObject).Should().Be("key_id");
        entity.FindProperty(nameof(EncryptionKeyRecord.Scope))!
            .GetColumnName(storeObject).Should().Be("scope");
        entity.FindProperty(nameof(EncryptionKeyRecord.WrappedCiphertext))!
            .GetColumnName(storeObject).Should().Be("wrapped_ciphertext");
        entity.FindProperty(nameof(EncryptionKeyRecord.WrappedProviderVersion))!
            .GetColumnName(storeObject).Should().Be("wrapped_provider_version");
        entity.FindProperty(nameof(EncryptionKeyRecord.CreatedAt))!
            .GetColumnName(storeObject).Should().Be("created_at");
        entity.FindProperty(nameof(EncryptionKeyRecord.ExpiresAt))!
            .GetColumnName(storeObject).Should().Be("expires_at");
        entity.FindProperty(nameof(EncryptionKeyRecord.IsActive))!
            .GetColumnName(storeObject).Should().Be("is_active");

        Microsoft.EntityFrameworkCore.Metadata.IIndex uniqueIndex = entity
            .GetIndexes()
            .Single(index => index.IsUnique);
        uniqueIndex.GetFilter().Should().Be("\"is_active\" = 1");
    }

    [Fact]
    public void AddVellumEncryptionKeys_WhenOptionsFromDiButNoUseVellum_ReadsFromApplicationServices()
    {
        // Issue #9 priority 2: when the consumer configures options ONLY via
        // AddEntityFrameworkCoreStore (no UseVellum on the DbContextOptionsBuilder), the
        // model builder extension still picks them up via IOptions<T> on the application
        // service provider.
        using SqliteConnection connection = new("DataSource=:memory:");
        connection.Open();

        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<AppServicesDiTestDbContext>(options => options.UseSqlite(connection));
        services.AddEntityFrameworkCoreStore<AppServicesDiTestDbContext>(opts =>
        {
            opts.TableName = "app_services_keys";
            opts.UniqueActiveIndexFilter = "\"IsActive\" = 1";
            opts.ScopeMaxLength = 77;
        });

        using ServiceProvider provider = services.BuildServiceProvider();
        using IServiceScope scope = provider.CreateScope();
        AppServicesDiTestDbContext context = scope.ServiceProvider
            .GetRequiredService<AppServicesDiTestDbContext>();

        Microsoft.EntityFrameworkCore.Metadata.IEntityType entity = context.Model
            .FindEntityType(typeof(EncryptionKeyRecord))!;

        entity.GetTableName().Should().Be("app_services_keys");
        entity.FindProperty(nameof(EncryptionKeyRecord.Scope))!
            .GetMaxLength().Should().Be(77);
    }

    [Fact]
    public void AddEntityFrameworkCoreStore_EmptyColumnName_FailsValidation()
    {
        // Issue #8: an empty column-name override would produce a silently broken migration.
        // The validator must trip at host start.
        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddEntityFrameworkCoreStore<TestDbContext>(opts =>
        {
            opts.KeyIdColumnName = "   ";
        });

        using ServiceProvider provider = services.BuildServiceProvider();
        IStartupValidator validator = provider.GetRequiredService<IStartupValidator>();

        Action act = validator.Validate;
        act.Should().Throw<OptionsValidationException>()
            .WithMessage("*KeyIdColumnName*");
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

        public Task<EncryptionKey> RotateAsync(EncryptionKey newKey, CancellationToken cancellationToken = default)
            => Task.FromResult(newKey);

        public Task<IReadOnlyList<EncryptionKey>> GetHistoricalAsync(string scope, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<EncryptionKey>>(Array.Empty<EncryptionKey>());

        public Task<IReadOnlyList<string>> GetActiveScopesAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());
    }
}
