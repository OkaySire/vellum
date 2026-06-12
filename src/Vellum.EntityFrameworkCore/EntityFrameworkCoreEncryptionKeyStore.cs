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
    public async Task<EncryptionKey> RotateAsync(EncryptionKey newKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(newKey);

        if (!newKey.IsActive)
        {
            throw new ArgumentException(
                $"RotateAsync requires an active key (IsActive = true); installing an inactive key would leave scope '{newKey.Scope}' with zero active keys.",
                nameof(newKey));
        }

        // Atomic swap: load the currently-active records (tracked, with IgnoreQueryFilters — L1),
        // flip them to inactive, add the new record, and commit everything in ONE SaveChangesAsync.
        // EF Core wraps a single SaveChanges in a single transaction, and the filtered unique
        // index on (Scope) WHERE IsActive is checked at the right time inside that transaction on
        // both SQLite and PostgreSQL — so either the whole rotation commits or nothing changes
        // and the old key stays active. No zero-active-key window, ever.
        List<EncryptionKeyRecord> active = await Records
            .IgnoreQueryFilters()
            .Where(k => k.Scope == newKey.Scope && k.IsActive)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        foreach (EncryptionKeyRecord record in active)
        {
            record.IsActive = false;
        }

        EncryptionKeyRecord candidate = EncryptionKeyRecord.FromDomain(newKey);
        Records.Add(candidate);

        try
        {
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            LogKeyRotated(_logger, newKey.KeyId, newKey.Scope, active.Count);
            return newKey;
        }
        catch (DbUpdateException ex)
        {
            // The transaction rolled back — nothing changed in the database. Detach every entity
            // we touched (the failed candidate AND the in-memory-deactivated records) so the
            // context stays usable for the caller and the tracker does not retry the flips on a
            // later SaveChanges.
            _context.Entry(candidate).State = EntityState.Detached;
            foreach (EncryptionKeyRecord record in active)
            {
                _context.Entry(record).State = EntityState.Detached;
            }

            // Re-read the active key (IgnoreQueryFilters via GetActiveAsync — L1). Two outcomes:
            //  - A concurrent rotation won: the active key is a FRESH key, not one of the keys we
            //    tried to deactivate. Return that winner, mirroring CreateAsync's race contract.
            //  - Anything else (transient DB failure, constraint on another column, ...): the old
            //    key is still active or no key is active. Rotation did NOT happen — surface the
            //    failure fail-closed instead of masking it behind the still-active old key.
            EncryptionKey? current = await GetActiveAsync(newKey.Scope, cancellationToken).ConfigureAwait(false);
            if (current is not null && !active.Exists(record => record.KeyId == current.KeyId))
            {
                LogRotateRaceDetected(_logger, newKey.KeyId, current.KeyId, newKey.Scope);
                return current;
            }

            throw new InvalidOperationException(
                $"Failed to rotate encryption key for scope '{newKey.Scope}'; the previously-active key is unchanged.",
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
    public async Task<EncryptionKey> UpdateWrappedKeyAsync(
        Guid keyId,
        string scope,
        WrappedKey newWrappedKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(newWrappedKey);

        // Tracked load (no AsNoTracking) so the mutation below is persisted by SaveChangesAsync.
        // IgnoreQueryFilters per L1 — DEK rows must never be hidden by the consumer's tenant
        // filter. Filtering by BOTH KeyId and Scope is the M1 defense: a caller cannot overwrite
        // another tenant's wrapped DEK by guessing a Guid.
        EncryptionKeyRecord? record = await Records
            .IgnoreQueryFilters()
            .Where(k => k.KeyId == keyId && k.Scope == scope)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (record is null)
        {
            // Fail closed: a silent no-op would let a rewrap sweep report success while data
            // still depends on the old KEK version.
            LogUpdateWrappedKeyMiss(_logger, keyId, scope);
            throw new InvalidOperationException(
                $"Encryption key {keyId} not found for scope '{scope}'; the wrapped key material was not updated.");
        }

        // Only the wrapped material changes — KeyId, Scope, CreatedAt, ExpiresAt, IsActive are
        // immutable under a rewrap.
        record.WrappedCiphertext = newWrappedKey.Ciphertext;
        record.WrappedProviderVersion = newWrappedKey.ProviderVersion;

        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        LogWrappedKeyUpdated(_logger, keyId, scope, newWrappedKey.ProviderVersion);
        return record.ToDomain();
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
        EventId = 5,
        Level = LogLevel.Information,
        Message = "Vellum EF Core store: rotated scope {Scope} — installed new active key {KeyId}, deactivated {DeactivatedCount} previous key(s) in one transaction.")]
    private static partial void LogKeyRotated(ILogger logger, Guid keyId, string scope, int deactivatedCount);

    [LoggerMessage(
        EventId = 6,
        Level = LogLevel.Information,
        Message = "Vellum EF Core store: rotation race detected — candidate {CandidateKeyId} lost to concurrent winner {WinnerKeyId} for scope {Scope}.")]
    private static partial void LogRotateRaceDetected(ILogger logger, Guid candidateKeyId, Guid winnerKeyId, string scope);

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

    [LoggerMessage(
        EventId = 7,
        Level = LogLevel.Information,
        Message = "Vellum EF Core store: updated wrapped key material for key {KeyId} in scope {Scope} (new provider version {ProviderVersion}).")]
    private static partial void LogWrappedKeyUpdated(ILogger logger, Guid keyId, string scope, string providerVersion);

    [LoggerMessage(
        EventId = 8,
        Level = LogLevel.Warning,
        Message = "Vellum EF Core store: UpdateWrappedKeyAsync miss for key {KeyId} under scope {Scope} — failing closed.")]
    private static partial void LogUpdateWrappedKeyMiss(ILogger logger, Guid keyId, string scope);
}
