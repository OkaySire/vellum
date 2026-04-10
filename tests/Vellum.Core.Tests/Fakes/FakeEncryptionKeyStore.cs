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

    public Task<EncryptionKey?> GetActiveAsync(string scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        lock (_lock)
        {
            EncryptionKey? active = _byId.Values
                .FirstOrDefault(k => k.IsActive && string.Equals(k.Scope, scope, StringComparison.Ordinal));
            return Task.FromResult<EncryptionKey?>(active);
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
