namespace Vellum.Rotation.Tests.Fakes;

/// <summary>
/// Minimal in-memory <see cref="IEncryptionKeyStore"/> for rotation-worker tests: holds one
/// active key per scope and serves the two members the worker uses
/// (<see cref="GetActiveScopesAsync"/> and <see cref="GetActiveAsync"/>). All other members
/// throw <see cref="NotSupportedException"/> so any unexpected store usage fails the test loudly.
/// </summary>
public sealed class FakeEncryptionKeyStore : IEncryptionKeyStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, EncryptionKey> _activeByScope = new(StringComparer.Ordinal);

    public int GetActiveScopesCalls { get; private set; }

    public int GetActiveCalls { get; private set; }

    public void SetActiveKey(string scope, DateTimeOffset createdAt)
    {
        lock (_gate)
        {
            _activeByScope[scope] = new EncryptionKey(
                KeyId: Guid.NewGuid(),
                Scope: scope,
                WrappedKey: new WrappedKey($"vault:v1:fake-{scope}", "1"),
                CreatedAt: createdAt,
                ExpiresAt: null,
                IsActive: true);
        }
    }

    public void RegisterScopeWithoutActiveKey(string scope)
    {
        lock (_gate)
        {
            // Listed by GetActiveScopesAsync but GetActiveAsync returns null — simulates a scope
            // revoked between the scope listing and the per-scope read.
            _activeByScope[scope] = null!;
        }
    }

    public Task<IReadOnlyList<string>> GetActiveScopesAsync(CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            GetActiveScopesCalls++;
            IReadOnlyList<string> scopes = [.. _activeByScope.Keys];
            return Task.FromResult(scopes);
        }
    }

    public Task<EncryptionKey?> GetActiveAsync(string scope, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            GetActiveCalls++;
            _ = _activeByScope.TryGetValue(scope, out EncryptionKey? key);
            return Task.FromResult(key);
        }
    }

    public Task<EncryptionKey?> GetByIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The rotation worker must not call GetByIdAsync.");

    public Task<EncryptionKey> CreateAsync(EncryptionKey key, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The rotation worker must not call CreateAsync.");

    public Task DeactivateAllAsync(string scope, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The rotation worker must not call DeactivateAllAsync.");

    public Task<EncryptionKey> RotateAsync(EncryptionKey newKey, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The rotation worker rotates via IDekManager, never via the store directly.");

    public Task<IReadOnlyList<EncryptionKey>> GetHistoricalAsync(string scope, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The rotation worker must not call GetHistoricalAsync.");

    public Task<EncryptionKey> UpdateWrappedKeyAsync(Guid keyId, string scope, WrappedKey newWrappedKey, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The rotation worker must not call UpdateWrappedKeyAsync.");
}
