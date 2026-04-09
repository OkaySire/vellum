using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Vellum.EntityFrameworkCore.Internal;

namespace Vellum.EntityFrameworkCore;

/// <summary>
/// Entity Framework Core-backed implementation of <see cref="IEncryptionKeyStore"/>.
/// </summary>
/// <typeparam name="TContext">The consumer's <see cref="DbContext"/> subclass.</typeparam>
/// <remarks>
/// <para>
/// The store is provider-agnostic at runtime: it only depends on <c>Microsoft.EntityFrameworkCore</c>
/// and <c>Microsoft.EntityFrameworkCore.Relational</c>. The consumer picks the concrete database
/// provider (SQL Server, PostgreSQL, SQLite, …) and configures the matching filtered-unique-index
/// filter via <see cref="VellumEntityFrameworkOptions.UniqueActiveIndexFilter"/>.
/// </para>
/// <para>
/// <b>IgnoreQueryFilters (lesson L1).</b> Every read path on this store chains
/// <see cref="EntityFrameworkQueryableExtensions.IgnoreQueryFilters{T}(IQueryable{T})"/>
/// before materialisation. DEKs are infrastructure — they must never be filtered by the
/// consumer's tenant query filter, otherwise creation races return <see langword="null"/>
/// for the winner. See <c>tasks/lessons.md</c> L1 for the production incident that drove
/// this rule.
/// </para>
/// <para>
/// <b>Race-safe creation (lesson L2).</b> <see cref="CreateAsync"/> uses a four-layer defence:
/// (1) double-check via <c>GetActiveAsync</c>, (2) attempt the insert, (3) on
/// <see cref="DbUpdateException"/> (raised by the filtered unique index), detach the failed
/// candidate from the tracker, (4) re-read and return the winner. The provider-specific SQL
/// error code is never inspected — EF Core normalises the error into <see cref="DbUpdateException"/>,
/// which keeps the store provider-agnostic.
/// </para>
/// <para>
/// <b>Multi-tenant defence (M1).</b> <see cref="GetByIdAsync"/> filters the query by both
/// <c>KeyId</c> and <c>Scope</c>, so a caller cannot retrieve another tenant's wrapped DEK
/// by guessing a <see cref="Guid"/>.
/// </para>
/// <para>
/// <b>Lifetime.</b> This store depends on <see cref="DbContext"/>, which is scoped by default,
/// so the store is registered as <c>Scoped</c> via
/// <see cref="VellumEntityFrameworkServiceCollectionExtensions"/>.
/// </para>
/// </remarks>
public sealed partial class EntityFrameworkCoreEncryptionKeyStore<TContext>(
    TContext context,
    ILogger<EntityFrameworkCoreEncryptionKeyStore<TContext>> logger) : IEncryptionKeyStore
    where TContext : DbContext
{
    private readonly TContext _context = context ?? throw new ArgumentNullException(nameof(context));
    private readonly ILogger<EntityFrameworkCoreEncryptionKeyStore<TContext>> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    private DbSet<EncryptionKeyRecord> Records => _context.Set<EncryptionKeyRecord>();

    /// <inheritdoc />
    public async Task<EncryptionKey?> GetActiveAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);

        EncryptionKeyRecord? record = await Records
            .AsNoTracking()
            .IgnoreQueryFilters()
            .Where(k => k.Scope == scope && k.IsActive)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        return record?.ToDomain();
    }

    /// <inheritdoc />
    public async Task<EncryptionKey?> GetByIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);

        // M1 defence: the query filters by BOTH KeyId and Scope, so a mismatch yields null
        // and no cross-tenant leak is possible even if a caller guesses a KeyId.
        EncryptionKeyRecord? record = await Records
            .AsNoTracking()
            .IgnoreQueryFilters()
            .Where(k => k.KeyId == keyId && k.Scope == scope)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (record is null)
        {
            // The caller may have supplied the wrong scope. Log (without leaking the KeyId
            // in a way that would pollute logs beyond standard structured logging).
            LogGetByIdMiss(_logger, keyId, scope);
        }

        return record?.ToDomain();
    }

    /// <inheritdoc />
    public async Task<EncryptionKey> CreateAsync(EncryptionKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);

        // Layer 1: double-check. If an active key already exists for this scope, return it
        // now. This is the common case when two callers try to bootstrap a scope concurrently
        // and the first one has already committed.
        EncryptionKey? existing = await GetActiveAsync(key.Scope, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            return existing;
        }

        // Layer 2: attempt the insert. The filtered unique index enforces uniqueness.
        EncryptionKeyRecord candidate = EncryptionKeyRecord.FromDomain(key);
        Records.Add(candidate);

        try
        {
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            LogKeyCreated(_logger, key.KeyId, key.Scope);
            return key;
        }
        catch (DbUpdateException ex)
        {
            // Layer 3: detach the failed candidate so the context stays usable for the caller.
            _context.Entry(candidate).State = EntityState.Detached;

            // Layer 4: re-read the winner via GetActiveAsync (which uses IgnoreQueryFilters).
            // If another caller inserted the active key for this scope just before us, it is
            // the winner and must be returned so the caller can re-unwrap it.
            EncryptionKey? winner = await GetActiveAsync(key.Scope, cancellationToken).ConfigureAwait(false);
            if (winner is not null)
            {
                LogCreateRaceDetected(_logger, key.KeyId, winner.KeyId, key.Scope);
                return winner;
            }

            // No winner surfaced — the update failure was caused by something else
            // (constraint on another column, transient error, ...). Surface it fail-closed.
            throw new InvalidOperationException(
                $"Failed to persist encryption key for scope '{key.Scope}' and no concurrent winner was found.",
                ex);
        }
    }

    /// <inheritdoc />
    public async Task DeactivateAllAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);

        List<EncryptionKeyRecord> active = await Records
            .IgnoreQueryFilters()
            .Where(k => k.Scope == scope && k.IsActive)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        if (active.Count == 0)
        {
            return;
        }

        foreach (EncryptionKeyRecord record in active)
        {
            record.IsActive = false;
        }

        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<EncryptionKey>> GetHistoricalAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);

        List<EncryptionKeyRecord> records = await Records
            .AsNoTracking()
            .IgnoreQueryFilters()
            .Where(k => k.Scope == scope)
            .OrderByDescending(k => k.CreatedAt)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        List<EncryptionKey> results = new(records.Count);
        foreach (EncryptionKeyRecord record in records)
        {
            results.Add(record.ToDomain());
        }

        LogHistoricalLoaded(_logger, scope, results.Count);
        return results;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> GetActiveScopesAsync(CancellationToken cancellationToken = default)
    {
        List<string> scopes = await Records
            .AsNoTracking()
            .IgnoreQueryFilters()
            .Where(k => k.IsActive)
            .Select(k => k.Scope)
            .Distinct()
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return scopes;
    }

    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Information,
        Message = "Vellum EF Core store: persisted new active encryption key {KeyId} for scope {Scope}.")]
    private static partial void LogKeyCreated(ILogger logger, Guid keyId, string scope);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Information,
        Message = "Vellum EF Core store: creation race detected — candidate {CandidateKeyId} lost to winner {WinnerKeyId} for scope {Scope}.")]
    private static partial void LogCreateRaceDetected(ILogger logger, Guid candidateKeyId, Guid winnerKeyId, string scope);

    [LoggerMessage(
        EventId = 3,
        Level = LogLevel.Debug,
        Message = "Vellum EF Core store: loaded {Count} historical key(s) for scope {Scope}.")]
    private static partial void LogHistoricalLoaded(ILogger logger, string scope, int count);

    [LoggerMessage(
        EventId = 4,
        Level = LogLevel.Debug,
        Message = "Vellum EF Core store: GetByIdAsync miss for key {KeyId} under scope {Scope}.")]
    private static partial void LogGetByIdMiss(ILogger logger, Guid keyId, string scope);
}
