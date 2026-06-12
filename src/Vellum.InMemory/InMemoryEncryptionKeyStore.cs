using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Vellum.InMemory;

/// <summary>
/// Thread-safe, process-local <see cref="IEncryptionKeyStore"/> backed by a
/// <see cref="ConcurrentDictionary{TKey,TValue}"/>. Intended for tests, samples, and local
/// development. State is held entirely in memory and is lost when the hosting process exits.
/// </summary>
/// <remarks>
/// <para>
/// <b>Not for production.</b> There is no persistence, no replication, and no expiration. A
/// process restart wipes every key.
/// </para>
/// <para>
/// <b>Thread-safety model.</b> Reads are lock-free against the underlying concurrent
/// dictionary. Writes are serialised through a single <see langword="lock"/> so the
/// one-active-key-per-scope invariant holds under concurrent <see cref="CreateAsync"/> and
/// <see cref="DeactivateAllAsync"/> calls. A global lock is intentional: the in-memory store
/// is only used by tests and samples, where contention is negligible and simplicity matters
/// more than scaling. If per-scope isolation were ever required, swapping the global lock for
/// a per-scope <see cref="System.Threading.SemaphoreSlim"/> would be a local, backwards-
/// compatible change.
/// </para>
/// <para>
/// <b>Race-safe creation.</b> <see cref="CreateAsync"/> honours the
/// <see cref="IEncryptionKeyStore"/> contract: if another caller already installed an active
/// key for the same scope, this call returns the existing winner rather than throwing. Callers
/// (notably <c>DekManager</c>) detect the race by comparing the returned
/// <see cref="EncryptionKey.KeyId"/> with the one they submitted and re-unwrap the winner when
/// they lose the race.
/// </para>
/// <para>
/// <b>Multi-tenant defence.</b> <see cref="GetByIdAsync"/> enforces scope equality before
/// returning a key — a caller asking for a key that belongs to a different scope gets
/// <see langword="null"/>, matching the behaviour EF Core-backed stores enforce via query
/// filters (see <c>tasks/lessons.md</c> L1).
/// </para>
/// </remarks>
public sealed partial class InMemoryEncryptionKeyStore : IEncryptionKeyStore
{
    private readonly ConcurrentDictionary<Guid, EncryptionKey> _keysById = new();
    private readonly object _writeLock = new();
    private readonly ILogger<InMemoryEncryptionKeyStore> _logger;

    /// <summary>
    /// Initializes a new instance with a <see cref="NullLogger{T}"/>. Kept for tests and
    /// samples that construct the store directly without DI.
    /// </summary>
    public InMemoryEncryptionKeyStore()
        : this(NullLogger<InMemoryEncryptionKeyStore>.Instance)
    {
    }

    /// <summary>
    /// Initializes a new instance with the specified logger. Used by DI.
    /// </summary>
    public InMemoryEncryptionKeyStore(ILogger<InMemoryEncryptionKeyStore> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public Task<EncryptionKey?> GetActiveAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        cancellationToken.ThrowIfCancellationRequested();

        EncryptionKey? active = _keysById.Values
            .FirstOrDefault(candidate =>
                candidate.IsActive && string.Equals(candidate.Scope, scope, StringComparison.Ordinal));

        return Task.FromResult(active);
    }

    /// <inheritdoc />
    public Task<EncryptionKey?> GetByIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        cancellationToken.ThrowIfCancellationRequested();

        if (!_keysById.TryGetValue(keyId, out EncryptionKey? key))
        {
            LogGetByIdMissNotFound(_logger, keyId, scope);
            return Task.FromResult<EncryptionKey?>(null);
        }

        // Multi-tenant defence: the caller must prove they know the scope the key belongs to.
        // A mismatch fails closed — return null, do not leak the key.
        if (!string.Equals(key.Scope, scope, StringComparison.Ordinal))
        {
            // M-6: log the scope mismatch so an in-memory-store-backed deployment emits the
            // same cross-tenant audit signal as the EF Core-backed store. Distinct message
            // from the plain-miss case above so consumers can SIEM-alert on it separately.
            LogGetByIdMissScopeMismatch(_logger, keyId, scope, key.Scope);
            return Task.FromResult<EncryptionKey?>(null);
        }

        return Task.FromResult<EncryptionKey?>(key);
    }

    [LoggerMessage(
        EventId = 2001,
        Level = LogLevel.Debug,
        Message = "In-memory store: key {KeyId} not found for scope {Scope}")]
    private static partial void LogGetByIdMissNotFound(ILogger logger, Guid keyId, string scope);

    [LoggerMessage(
        EventId = 2002,
        Level = LogLevel.Warning,
        Message = "In-memory store: key {KeyId} was requested for scope {RequestedScope} but belongs to scope {ActualScope}")]
    private static partial void LogGetByIdMissScopeMismatch(ILogger logger, Guid keyId, string requestedScope, string actualScope);

    [LoggerMessage(
        EventId = 2003,
        Level = LogLevel.Warning,
        Message = "In-memory store: UpdateWrappedKeyAsync for key {KeyId} was requested for scope {RequestedScope} but the key belongs to scope {ActualScope} — failing closed")]
    private static partial void LogUpdateWrappedKeyScopeMismatch(ILogger logger, Guid keyId, string requestedScope, string actualScope);

    /// <inheritdoc />
    public Task<EncryptionKey> CreateAsync(EncryptionKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        cancellationToken.ThrowIfCancellationRequested();

        lock (_writeLock)
        {
            // Race-safe check under the write lock: if another caller already installed an
            // active key for this scope, return the winner. The caller detects the race by
            // inspecting the returned KeyId.
            EncryptionKey? winner = FindActiveForScopeUnlocked(key.Scope);
            if (winner is not null)
            {
                return Task.FromResult(winner);
            }

            _keysById[key.KeyId] = key;
            return Task.FromResult(key);
        }
    }

    /// <inheritdoc />
    public Task<EncryptionKey> RotateAsync(EncryptionKey newKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(newKey);
        cancellationToken.ThrowIfCancellationRequested();

        if (!newKey.IsActive)
        {
            throw new ArgumentException(
                $"RotateAsync requires an active key (IsActive = true); installing an inactive key would leave scope '{newKey.Scope}' with zero active keys.",
                nameof(newKey));
        }

        // Atomic swap under the global write lock: deactivate every active key for the scope and
        // install the new active key in one critical section. In-memory mutations cannot fail
        // half-way, so this call always wins — concurrent rotations simply serialise, each
        // installing its key as the new active one.
        lock (_writeLock)
        {
            foreach (KeyValuePair<Guid, EncryptionKey> entry in _keysById.ToArray())
            {
                EncryptionKey current = entry.Value;
                if (current.IsActive && string.Equals(current.Scope, newKey.Scope, StringComparison.Ordinal))
                {
                    _keysById[entry.Key] = current with { IsActive = false };
                }
            }

            _keysById[newKey.KeyId] = newKey;
        }

        return Task.FromResult(newKey);
    }

    /// <inheritdoc />
    public Task DeactivateAllAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        cancellationToken.ThrowIfCancellationRequested();

        lock (_writeLock)
        {
            // Snapshot-then-mutate: iterating the dictionary while updating it is safe on
            // ConcurrentDictionary but a snapshot keeps the intent obvious and avoids any
            // implementation-specific iteration semantics.
            foreach (KeyValuePair<Guid, EncryptionKey> entry in _keysById.ToArray())
            {
                EncryptionKey current = entry.Value;
                if (current.IsActive && string.Equals(current.Scope, scope, StringComparison.Ordinal))
                {
                    _keysById[entry.Key] = current with { IsActive = false };
                }
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<EncryptionKey> UpdateWrappedKeyAsync(
        Guid keyId,
        string scope,
        WrappedKey newWrappedKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(newWrappedKey);
        cancellationToken.ThrowIfCancellationRequested();

        lock (_writeLock)
        {
            if (!_keysById.TryGetValue(keyId, out EncryptionKey? existing))
            {
                // Fail closed: a silent no-op would let a rewrap sweep report success while
                // data still depends on the old KEK version.
                throw new InvalidOperationException(
                    $"Encryption key {keyId} not found for scope '{scope}'; the wrapped key material was not updated.");
            }

            // Multi-tenant defense (M1): the caller must prove they know the scope the key
            // belongs to. A mismatch fails closed and never reveals the other scope.
            if (!string.Equals(existing.Scope, scope, StringComparison.Ordinal))
            {
                LogUpdateWrappedKeyScopeMismatch(_logger, keyId, scope, existing.Scope);
                throw new InvalidOperationException(
                    $"Encryption key {keyId} not found for scope '{scope}'; the wrapped key material was not updated.");
            }

            // Only the wrapped material changes — KeyId, Scope, CreatedAt, ExpiresAt, IsActive
            // are immutable under a rewrap.
            EncryptionKey updated = existing with { WrappedKey = newWrappedKey };
            _keysById[keyId] = updated;
            return Task.FromResult(updated);
        }
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<EncryptionKey>> GetHistoricalAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        cancellationToken.ThrowIfCancellationRequested();

        List<EncryptionKey> matches = _keysById.Values
            .Where(candidate => string.Equals(candidate.Scope, scope, StringComparison.Ordinal))
            .ToList();

        matches.Sort(static (left, right) => right.CreatedAt.CompareTo(left.CreatedAt));
        return Task.FromResult<IReadOnlyList<EncryptionKey>>(matches);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<string>> GetActiveScopesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        HashSet<string> scopes = new(
            _keysById.Values.Where(key => key.IsActive).Select(key => key.Scope),
            StringComparer.Ordinal);

        List<string> result = new(scopes);
        return Task.FromResult<IReadOnlyList<string>>(result);
    }

    private EncryptionKey? FindActiveForScopeUnlocked(string scope)
    {
        return _keysById.Values
            .FirstOrDefault(candidate =>
                candidate.IsActive && string.Equals(candidate.Scope, scope, StringComparison.Ordinal));
    }
}
