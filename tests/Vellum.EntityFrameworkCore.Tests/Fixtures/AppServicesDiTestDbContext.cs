using Microsoft.EntityFrameworkCore;
using Vellum.EntityFrameworkCore;

namespace Vellum.EntityFrameworkCore.Tests.Fixtures;

/// <summary>
/// Dedicated <see cref="DbContext"/> type for the "options resolved from application
/// service provider (no <c>UseVellum</c>)" test. Proves that
/// <c>AddEntityFrameworkCoreStore&lt;T&gt;(configure)</c> is sufficient to flow options
/// into the model builder via <c>CoreOptionsExtension.ApplicationServiceProvider</c>.
/// </summary>
public sealed class AppServicesDiTestDbContext(DbContextOptions<AppServicesDiTestDbContext> options) : DbContext(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        base.OnModelCreating(modelBuilder);
        modelBuilder.AddVellumEncryptionKeys(this);
    }
}
