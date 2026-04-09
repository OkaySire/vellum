using System.Collections.Concurrent;

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
public sealed class InMemoryEncryptionKeyStore : IEncryptionKeyStore
{
    private readonly ConcurrentDictionary<Guid, EncryptionKey> _keysById = new();
    private readonly object _writeLock = new();

    /// <inheritdoc />
    public Task<EncryptionKey?> GetActiveAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        cancellationToken.ThrowIfCancellationRequested();

        EncryptionKey? active = null;
        foreach (KeyValuePair<Guid, EncryptionKey> entry in _keysById)
        {
            EncryptionKey candidate = entry.Value;
            if (candidate.IsActive && string.Equals(candidate.Scope, scope, StringComparison.Ordinal))
            {
                active = candidate;
                break;
            }
        }

        return Task.FromResult(active);
    }

    /// <inheritdoc />
    public Task<EncryptionKey?> GetByIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        cancellationToken.ThrowIfCancellationRequested();

        if (!_keysById.TryGetValue(keyId, out EncryptionKey? key))
        {
            return Task.FromResult<EncryptionKey?>(null);
        }

        // Multi-tenant defence: the caller must prove they know the scope the key belongs to.
        // A mismatch fails closed — return null, do not leak the key.
        if (!string.Equals(key.Scope, scope, StringComparison.Ordinal))
        {
            return Task.FromResult<EncryptionKey?>(null);
        }

        return Task.FromResult<EncryptionKey?>(key);
    }

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
    public Task<IReadOnlyList<EncryptionKey>> GetHistoricalAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        cancellationToken.ThrowIfCancellationRequested();

        List<EncryptionKey> matches = new();
        foreach (KeyValuePair<Guid, EncryptionKey> entry in _keysById)
        {
            EncryptionKey candidate = entry.Value;
            if (string.Equals(candidate.Scope, scope, StringComparison.Ordinal))
            {
                matches.Add(candidate);
            }
        }

        matches.Sort(static (left, right) => right.CreatedAt.CompareTo(left.CreatedAt));
        return Task.FromResult<IReadOnlyList<EncryptionKey>>(matches);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<string>> GetActiveScopesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        HashSet<string> scopes = new(StringComparer.Ordinal);
        foreach (KeyValuePair<Guid, EncryptionKey> entry in _keysById)
        {
            if (entry.Value.IsActive)
            {
                scopes.Add(entry.Value.Scope);
            }
        }

        List<string> result = new(scopes);
        return Task.FromResult<IReadOnlyList<string>>(result);
    }

    private EncryptionKey? FindActiveForScopeUnlocked(string scope)
    {
        foreach (KeyValuePair<Guid, EncryptionKey> entry in _keysById)
        {
            EncryptionKey candidate = entry.Value;
            if (candidate.IsActive && string.Equals(candidate.Scope, scope, StringComparison.Ordinal))
            {
                return candidate;
            }
        }

        return null;
    }
}
