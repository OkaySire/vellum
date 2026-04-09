using Vellum.EntityFrameworkCore;

namespace Vellum.EntityFrameworkCore.Tests.Fixtures;

/// <summary>
/// Carries the <see cref="VellumEntityFrameworkOptions"/> used by the next
/// <see cref="TestDbContext"/> construction. The test DbContext constructor is
/// parameterless-by-EF-Core-convention, so tests flow options through this static slot
/// before newing up a context.
/// </summary>
public static class TestOptionsAccessor
{
    /// <summary>
    /// The options that the next constructed <see cref="TestDbContext"/> will bind against.
    /// Defaults to SQLite-compatible filter syntax since all tests run on in-memory SQLite.
    /// </summary>
    public static VellumEntityFrameworkOptions Current { get; set; } = new VellumEntityFrameworkOptions
    {
        UniqueActiveIndexFilter = "\"IsActive\" = 1",
    };
}
