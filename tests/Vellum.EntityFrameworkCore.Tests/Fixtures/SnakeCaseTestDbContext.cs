using Microsoft.EntityFrameworkCore;
using Vellum.EntityFrameworkCore;

namespace Vellum.EntityFrameworkCore.Tests.Fixtures;

/// <summary>
/// Dedicated <see cref="DbContext"/> type for the snake_case column-name override test.
/// EF Core caches the model per <see cref="DbContext"/> CLR type, so giving this test its
/// own type ensures its seven renamed columns do not leak into the caches shared by
/// sibling tests.
/// </summary>
public sealed class SnakeCaseTestDbContext(DbContextOptions<SnakeCaseTestDbContext> options) : DbContext(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        base.OnModelCreating(modelBuilder);
        modelBuilder.AddVellumEncryptionKeys(this);
    }
}
