using System.Globalization;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Vellum.EntityFrameworkCore;

namespace Vellum.EntityFrameworkCore.Tests.Fixtures;

/// <summary>
/// Creates a disposable shared-cache SQLite in-memory database + <see cref="TestDbContext"/> +
/// store tuple for a single test. Uses the <c>file::memory:?cache=shared</c> pattern with a
/// unique name per harness so that concurrent DbContext instances can each open their own
/// connection to the same in-memory database without colliding on EF Core's per-connection
/// SQLite function registration.
/// </summary>
/// <remarks>
/// A single "keep-alive" connection is held open for the lifetime of the harness; SQLite keeps
/// the in-memory database alive as long as at least one connection is connected to it.
/// </remarks>
public sealed class TestHarness : IAsyncDisposable
{
    private readonly string _databasePath;
    private readonly string _connectionString;
    private readonly List<TestDbContext> _contexts = new();

    public TestHarness(VellumEntityFrameworkOptions? vellumOptions = null)
    {
        TestOptionsAccessor.Current = vellumOptions ?? new VellumEntityFrameworkOptions
        {
            UniqueActiveIndexFilter = "\"IsActive\" = 1",
        };

        // Temp-file SQLite: all contexts opened against the same path share the database
        // and each gets its own connection — which sidesteps both the "active statements"
        // limitation of a single shared SqliteConnection and the shared-cache quirks of
        // in-memory Microsoft.Data.Sqlite pooling. The file is removed in DisposeAsync.
        // Path.Join (not Path.Combine) is used on purpose: the filename is fully controlled
        // here (constant prefix + Guid) so the absolute-path semantics of Path.Combine would
        // be a footgun for nothing, and CodeQL's cs/path-combine rule flags the ambiguity.
        string fileName = string.Create(
            CultureInfo.InvariantCulture,
            $"vellum-test-{Guid.NewGuid():N}.sqlite");
        _databasePath = Path.Join(Path.GetTempPath(), fileName);
        _connectionString = $"Data Source={_databasePath};Pooling=False";

        // Primary context + store the test uses by default. EnsureCreated bootstraps the
        // schema; any subsequently created context sees the same underlying file.
        Context = CreateContext();
        Context.Database.EnsureCreated();
        Store = new EntityFrameworkCoreEncryptionKeyStore<TestDbContext>(
            Context,
            NullLogger<EntityFrameworkCoreEncryptionKeyStore<TestDbContext>>.Instance);
    }

    public TestDbContext Context { get; }

    public EntityFrameworkCoreEncryptionKeyStore<TestDbContext> Store { get; }

    public TestDbContext CreateContext()
    {
        DbContextOptions<TestDbContext> options = new DbContextOptionsBuilder<TestDbContext>()
            .UseSqlite(_connectionString)
            .Options;

        TestDbContext context = new TestDbContext(options);
        _contexts.Add(context);
        return context;
    }

    public EntityFrameworkCoreEncryptionKeyStore<TestDbContext> CreateStore()
    {
        TestDbContext context = CreateContext();
        return new EntityFrameworkCoreEncryptionKeyStore<TestDbContext>(
            context,
            NullLogger<EntityFrameworkCoreEncryptionKeyStore<TestDbContext>>.Instance);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (TestDbContext context in _contexts)
        {
            await context.DisposeAsync().ConfigureAwait(false);
        }

        // Microsoft.Data.Sqlite keeps an internal connection pool even with Pooling=False
        // on some platforms; SqliteConnection.ClearAllPools() guarantees the file handle is
        // released before we delete the temp file.
        SqliteConnection.ClearAllPools();

        try
        {
            if (File.Exists(_databasePath))
            {
                File.Delete(_databasePath);
            }
        }
        catch (IOException)
        {
            // Best-effort cleanup — temp files left behind on a failed test run are harmless.
        }
    }
}
