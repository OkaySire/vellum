using Microsoft.EntityFrameworkCore;
using Vellum.EntityFrameworkCore;

namespace Vellum.EntityFrameworkCore.Tests.Fixtures;

/// <summary>
/// A separate <see cref="DbContext"/> type used exclusively by the filter-override
/// assertion test. EF Core caches the model per <see cref="DbContext"/> CLR type, so
/// giving the filter-override test its own type ensures its custom
/// <see cref="VellumEntityFrameworkOptions"/> do not leak into the cache shared by
/// <see cref="TestDbContext"/>.
/// </summary>
public sealed class FilterOverrideTestDbContext(DbContextOptions<FilterOverrideTestDbContext> options) : DbContext(options)
{
    /// <summary>
    /// Static slot the test assigns before constructing this context. Picked up by
    /// <see cref="OnModelCreating"/> on first use.
    /// </summary>
    public static VellumEntityFrameworkOptions VellumOptions { get; set; } = new();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        base.OnModelCreating(modelBuilder);
        modelBuilder.AddVellumEncryptionKeys(VellumOptions);
    }
}
