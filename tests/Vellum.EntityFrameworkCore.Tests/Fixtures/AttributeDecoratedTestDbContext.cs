using Microsoft.EntityFrameworkCore;
using Vellum.EntityFrameworkCore;

namespace Vellum.EntityFrameworkCore.Tests.Fixtures;

/// <summary>
/// Dedicated <see cref="DbContext"/> type that exercises the
/// <see cref="VellumEntityFrameworkOptionsAttribute"/> resolution path. EF Core caches
/// the model per <see cref="DbContext"/> CLR type, so giving this test its own type
/// ensures its attribute-derived column names do not leak into the caches shared by
/// sibling tests.
/// </summary>
/// <remarks>
/// This context intentionally mirrors the jacqcloud-buses snake_case schema that
/// triggered issue #17. No <c>UseVellum</c> call is required at options-build time —
/// the attribute is the single source of truth, which is the whole point of the fix.
/// </remarks>
[VellumEntityFrameworkOptions(
    TableName = "bus_encryption_keys",
    KeyIdColumnName = "key_id",
    ScopeColumnName = "scope",
    WrappedCiphertextColumnName = "wrapped_ciphertext",
    WrappedProviderVersionColumnName = "wrapped_provider_version",
    CreatedAtColumnName = "created_at",
    ExpiresAtColumnName = "expires_at",
    IsActiveColumnName = "is_active",
    UniqueActiveIndexFilter = "\"is_active\" = 1")]
public sealed class AttributeDecoratedTestDbContext(DbContextOptions<AttributeDecoratedTestDbContext> options)
    : DbContext(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        base.OnModelCreating(modelBuilder);
        modelBuilder.AddVellumEncryptionKeys(this);
    }
}
