using Microsoft.EntityFrameworkCore;
using Vellum.EntityFrameworkCore;

namespace Vellum.EntityFrameworkCore.Tests.Fixtures;

/// <summary>
/// Dedicated <see cref="DbContext"/> type for the default-column-names assertion test.
/// EF Core caches the model per <see cref="DbContext"/> CLR type, so giving this test its
/// own type ensures it observes the out-of-the-box PascalCase layout without interference
/// from sibling column-name tests.
/// </summary>
public sealed class DefaultColumnsTestDbContext(DbContextOptions<DefaultColumnsTestDbContext> options) : DbContext(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        base.OnModelCreating(modelBuilder);
        modelBuilder.AddVellumEncryptionKeys(this);
    }
}
