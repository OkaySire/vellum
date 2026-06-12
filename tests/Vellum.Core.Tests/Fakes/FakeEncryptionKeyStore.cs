using System.Collections.Concurrent;
using System.Linq;

namespace Vellum.Tests.Fakes;

/// <summary>
/// In-memory <see cref="IEncryptionKeyStore"/> for tests. Thread-safe. Simulates the
/// unique-index semantics the production EF Core store must uphold: only one active key per
/// scope, and <see cref="CreateAsync"/> returns the winner if another caller raced ahead.
/// </summary>
public sealed class FakeEncryptionKeyStore : IEncryptionKeyStore
{
    private readonly ConcurrentDictionary<Guid, EncryptionKey> _byId = new();
    private readonly object _lock = new();

    public int CreateCalls { get; private set; }

    public int DeactivateCalls { get; private set; }

    public int RotateCalls { get; private set; }

    public int UpdateWrappedKeyCalls { get; private set; }

    /// <summary>
    /// Test hook: when set, awaited at the start of <see cref="GetActiveAsync"/> (before the
    /// store is consulted). Lets tests pause an in-flight slow read at a precise point to
    /// orchestrate read-vs-rotate interleavings deterministically.
    /// </summary>
    public Func<string, Task>? GetActiveDelay { get; set; }

    public async Task<EncryptionKey?> GetActiveAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);

        Func<string, Task>? delay = GetActiveDelay;
        if (delay is not null)
        {
            await delay(scope).ConfigureAwait(false);
        }

        lock (_lock)
        {
            EncryptionKey? active = _byId.Values
                .FirstOrDefault(k => k.IsActive && string.Equals(k.Scope, scope, StringComparison.Ordinal));
            return active;
        }
    }

    public Task<EncryptionKey?> GetByIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (!_byId.TryGetValue(keyId, out EncryptionKey? key))
        {
            return Task.FromResult<EncryptionKey?>(null);
        }

        // Multi-tenant defense: enforce scope match at the store level.
        if (!string.Equals(key.Scope, scope, StringComparison.Ordinal))
        {
            return Task.FromResult<EncryptionKey?>(null);
        }

        return Task.FromResult<EncryptionKey?>(key);
    }

    public Task<EncryptionKey> CreateAsync(EncryptionKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        CreateCalls++;
        lock (_lock)
        {
            EncryptionKey? winner = _byId.Values
                .FirstOrDefault(k => k.IsActive && string.Equals(k.Scope, key.Scope, StringComparison.Ordinal));
            if (winner is not null)
            {
                return Task.FromResult(winner);
            }

            _byId[key.KeyId] = key;
            return Task.FromResult(key);
        }
    }

    public Task<EncryptionKey> RotateAsync(EncryptionKey newKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(newKey);
        if (!newKey.IsActive)
        {
            throw new ArgumentException(
                "RotateAsync requires an active key (IsActive = true).",
                nameof(newKey));
        }

        RotateCalls++;
        lock (_lock)
        {
            // Atomic swap under the lock: deactivate all active keys for the scope, then
            // install the new active key — mirroring the transactional semantics of the
            // production EF Core store.
            KeyValuePair<Guid, EncryptionKey>[] targets = _byId
                .Where(entry => string.Equals(entry.Value.Scope, newKey.Scope, StringComparison.Ordinal) && entry.Value.IsActive)
                .ToArray();
            foreach (KeyValuePair<Guid, EncryptionKey> entry in targets)
            {
                _byId[entry.Key] = entry.Value with { IsActive = false };
            }

            _byId[newKey.KeyId] = newKey;
            return Task.FromResult(newKey);
        }
    }

    public Task DeactivateAllAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        DeactivateCalls++;
        lock (_lock)
        {
            KeyValuePair<Guid, EncryptionKey>[] targets = _byId
                .Where(entry => string.Equals(entry.Value.Scope, scope, StringComparison.Ordinal) && entry.Value.IsActive)
                .ToArray();
            foreach (KeyValuePair<Guid, EncryptionKey> entry in targets)
            {
                _byId[entry.Key] = entry.Value with { IsActive = false };
            }
        }

        return Task.CompletedTask;
    }

    public Task<EncryptionKey> UpdateWrappedKeyAsync(Guid keyId, string scope, WrappedKey newWrappedKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(newWrappedKey);
        UpdateWrappedKeyCalls++;

        lock (_lock)
        {
            if (!_byId.TryGetValue(keyId, out EncryptionKey? existing)
                || !string.Equals(existing.Scope, scope, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Encryption key {keyId} not found for scope '{scope}'; the wrapped key material was not updated.");
            }

            EncryptionKey updated = existing with { WrappedKey = newWrappedKey };
            _byId[keyId] = updated;
            return Task.FromResult(updated);
        }
    }

    public Task<IReadOnlyList<EncryptionKey>> GetHistoricalAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        lock (_lock)
        {
            IReadOnlyList<EncryptionKey> keys = _byId.Values
                .Where(k => string.Equals(k.Scope, scope, StringComparison.Ordinal))
                .OrderByDescending(k => k.CreatedAt)
                .ToList();
            return Task.FromResult(keys);
        }
    }

    public Task<IReadOnlyList<string>> GetActiveScopesAsync(CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            IReadOnlyList<string> scopes = _byId.Values
                .Where(k => k.IsActive)
                .Select(k => k.Scope)
                .Distinct(StringComparer.Ordinal)
                .ToList();
            return Task.FromResult(scopes);
        }
    }

    /// <summary>
    /// Test hook: inject a pre-existing active key into the store to simulate a race.
    /// </summary>
    public void SeedKey(EncryptionKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _byId[key.KeyId] = key;
    }
}
