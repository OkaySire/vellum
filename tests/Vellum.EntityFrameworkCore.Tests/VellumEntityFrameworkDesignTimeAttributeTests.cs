using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Vellum.EntityFrameworkCore.Internal;
using Vellum.EntityFrameworkCore.Tests.Fixtures;
using Xunit;

namespace Vellum.EntityFrameworkCore.Tests;

/// <summary>
/// Pins the <see cref="VellumEntityFrameworkOptionsAttribute"/> resolution path that
/// closes issue #17. The attribute lets a consumer's
/// <c>IDesignTimeDbContextFactory&lt;T&gt;</c> produce <see cref="DbContextOptions"/>
/// without calling <c>UseVellum(...)</c> and still have the scaffolder observe the
/// configured column-name overrides, so <c>dotnet ef migrations add</c> no longer has to
/// be kept in sync with a runtime <c>AddDbContext</c> call.
/// </summary>
public sealed class VellumEntityFrameworkDesignTimeAttributeTests
{
    [Fact]
    public void Model_ReadsOptions_FromAttribute_WhenUseVellumAbsent()
    {
        // Arrange: the "design-time factory" path — options built WITHOUT UseVellum, so
        // the only source of column-name overrides is the attribute on the context type.
        using SqliteConnection connection = new("DataSource=:memory:");
        connection.Open();

        DbContextOptions<AttributeDecoratedTestDbContext> dbOptions =
            new DbContextOptionsBuilder<AttributeDecoratedTestDbContext>()
                .UseSqlite(connection)
                .Options;

        // Act
        using AttributeDecoratedTestDbContext context = new(dbOptions);
        IEntityType entity = context.Model.FindEntityType(typeof(EncryptionKeyRecord))!;

        // Assert: the attribute's values flow into the model even though UseVellum was
        // never called on the options builder.
        entity.GetTableName().Should().Be("bus_encryption_keys");

        StoreObjectIdentifier storeObject = StoreObjectIdentifier.Table(
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

        IIndex uniqueIndex = entity.GetIndexes().Single(index => index.IsUnique);
        uniqueIndex.GetFilter().Should().Be("\"is_active\" = 1");
    }
}
