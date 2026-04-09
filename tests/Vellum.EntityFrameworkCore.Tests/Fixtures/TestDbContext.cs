using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Vellum.EntityFrameworkCore;
using Vellum.EntityFrameworkCore.Internal;

namespace Vellum.EntityFrameworkCore.Tests.Fixtures;

/// <summary>
/// Minimal DbContext used by the Vellum.EntityFrameworkCore tests. Registers the wrapped-DEK
/// entity via <see cref="VellumModelBuilderExtensions.AddVellumEncryptionKeys"/>, then layers
/// a global query filter directly on <see cref="EncryptionKeyRecord"/> that matches
/// <b>nothing</b>. If the Vellum store ever stops calling
/// <see cref="EntityFrameworkQueryableExtensions.IgnoreQueryFilters{T}(IQueryable{T})"/>,
/// every read through the store returns zero rows and the
/// <c>IgnoreQueryFilters_TenantFilterSet_StillReadsKeys</c> test fails — which is exactly
/// how we pin lesson L1 at the test layer.
/// </summary>
public sealed class TestDbContext(DbContextOptions<TestDbContext> options) : DbContext(options)
{
    private readonly VellumEntityFrameworkOptions _vellumOptions = TestOptionsAccessor.Current;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        base.OnModelCreating(modelBuilder);

        modelBuilder.AddVellumEncryptionKeys(_vellumOptions);

        // SQLite has no native DateTimeOffset storage or ORDER BY support. Every SQLite-backed
        // consumer (and our tests) must map DateTimeOffset columns through a value converter.
        // Store UTC ticks as long — simple, lossless, sortable.
        ValueConverter<DateTimeOffset, long> dtoConverter = new(
            static v => v.UtcTicks,
            static v => new DateTimeOffset(v, TimeSpan.Zero));
        ValueConverter<DateTimeOffset?, long?> nullableDtoConverter = new(
            static v => v.HasValue ? v.Value.UtcTicks : (long?)null,
            static v => v.HasValue ? new DateTimeOffset(v.Value, TimeSpan.Zero) : (DateTimeOffset?)null);

        modelBuilder.Entity<EncryptionKeyRecord>(entity =>
        {
            entity.Property(k => k.CreatedAt).HasConversion(dtoConverter);
            entity.Property(k => k.ExpiresAt).HasConversion(nullableDtoConverter);
            entity.HasQueryFilter(k => k.Scope == "__impossible__");
        });
    }
}
