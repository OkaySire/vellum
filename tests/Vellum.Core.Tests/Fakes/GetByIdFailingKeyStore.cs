namespace Vellum.Tests.Fakes;

/// <summary>
/// Decorates an <see cref="IEncryptionKeyStore"/> and makes
/// <see cref="GetByIdAsync(Guid, string, CancellationToken)"/> throw a caller-supplied exception,
/// delegating every other member to the inner store untouched.
/// </summary>
/// <remarks>
/// <para>
/// Exists because the store-first decrypt path must be provoked into failing <b>at the lookup</b>,
/// with an exception of a chosen shape, while the rest of the store keeps behaving normally so the
/// envelope-copy fallback has a real store behind it (the write path seeds the key through this same
/// object).
/// </para>
/// <para>
/// Two shapes matter, and neither can be produced by <see cref="FakeEncryptionKeyStore"/> alone:
/// a <see cref="TaskCanceledException"/> that is an <see cref="OperationCanceledException"/> without
/// the caller's token ever being cancelled (an <c>HttpClient</c> timeout), and an infrastructure
/// exception whose message carries a host and port.
/// </para>
/// </remarks>
public sealed class GetByIdFailingKeyStore(IEncryptionKeyStore inner, Func<Exception> failure) : IEncryptionKeyStore
{
    /// <summary>Number of times the decorated lookup was reached.</summary>
    public int GetByIdCalls { get; private set; }

    public Task<EncryptionKey?> GetByIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default)
    {
        GetByIdCalls++;
        throw failure();
    }

    public Task<EncryptionKey?> GetActiveAsync(string scope, CancellationToken cancellationToken = default)
        => inner.GetActiveAsync(scope, cancellationToken);

    public Task<EncryptionKey> CreateAsync(EncryptionKey key, CancellationToken cancellationToken = default)
        => inner.CreateAsync(key, cancellationToken);

    public Task DeactivateAllAsync(string scope, CancellationToken cancellationToken = default)
        => inner.DeactivateAllAsync(scope, cancellationToken);

    public Task<EncryptionKey> RotateAsync(EncryptionKey newKey, CancellationToken cancellationToken = default)
        => inner.RotateAsync(newKey, cancellationToken);

    public Task<EncryptionKey> UpdateWrappedKeyAsync(Guid keyId, string scope, WrappedKey newWrappedKey, CancellationToken cancellationToken = default)
        => inner.UpdateWrappedKeyAsync(keyId, scope, newWrappedKey, cancellationToken);

    public Task<IReadOnlyList<EncryptionKey>> GetHistoricalAsync(string scope, CancellationToken cancellationToken = default)
        => inner.GetHistoricalAsync(scope, cancellationToken);

    public Task<IReadOnlyList<string>> GetActiveScopesAsync(CancellationToken cancellationToken = default)
        => inner.GetActiveScopesAsync(cancellationToken);
}
