using Microsoft.EntityFrameworkCore;
using Vellum.EntityFrameworkCore;

namespace Vellum.EntityFrameworkCore.Tests.Fixtures;

/// <summary>
/// A separate <see cref="DbContext"/> type used exclusively by the filter-override and
/// column-name-override assertion tests. EF Core caches the model per
/// <see cref="DbContext"/> CLR type, so giving these tests their own type ensures their
/// custom <see cref="VellumEntityFrameworkOptions"/> do not leak into the cache shared by
/// <see cref="TestDbContext"/>.
/// </summary>
/// <remarks>
/// Options flow through <see cref="VellumDbContextOptionsBuilderExtensions.UseVellum{TContext}(DbContextOptionsBuilder{TContext}, Action{VellumEntityFrameworkOptions}?)"/>
/// on the <see cref="DbContextOptionsBuilder{TContext}"/>, so these tests exercise the
/// issue #9 single-source configuration path.
/// </remarks>
public sealed class FilterOverrideTestDbContext(DbContextOptions<FilterOverrideTestDbContext> options) : DbContext(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        base.OnModelCreating(modelBuilder);
        modelBuilder.AddVellumEncryptionKeys(this);
    }
}
