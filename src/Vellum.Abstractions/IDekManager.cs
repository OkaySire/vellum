namespace Vellum;

/// <summary>
/// Manages the lifecycle of Data Encryption Keys (DEKs) for a given scope, coordinating the
/// <see cref="IKeyEncryptionProvider"/> and <see cref="IEncryptionKeyStore"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Caching.</b> Implementations are expected to cache active DEKs in memory with a configurable TTL
/// so that the hot path of encryption does not require a round-trip to the KEK provider. Cached
/// key material must be cloned before being returned to callers — see
/// <c>tasks/lessons.md</c> L3 for the rationale.
/// </para>
/// <para>
/// <b>Race-safe DEK creation.</b> When two callers simultaneously request a DEK for a fresh scope,
/// only one creation succeeds. Implementations must detect the unique-index violation, detach the
/// failed entity, and return the winner. See <c>tasks/lessons.md</c> L2.
/// </para>
/// <para>
/// <b>ValueTask on the hot path.</b> <see cref="GetActiveDekAsync(string, System.Threading.CancellationToken)"/>
/// and <see cref="GetDekByKeyIdAsync(System.Guid, string, System.Threading.CancellationToken)"/>
/// return <see cref="ValueTask{TResult}"/> so that cache-hits stay fully synchronous and
/// allocation-free. Implementations should complete synchronously when the requested DEK is
/// already in cache, and fall back to an async path only on cache miss.
/// </para>
/// </remarks>
public interface IDekManager
{
    /// <summary>
    /// Returns the active DEK for the given scope, creating one if none exists.
    /// </summary>
    /// <remarks>
    /// Cache-hit-is-sync: implementations should return a completed <see cref="ValueTask{TResult}"/>
    /// when the DEK for <paramref name="scope"/> is already cached.
    /// </remarks>
    /// <param name="scope">Opaque scope identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<Dek> GetActiveDekAsync(string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new DEK for the given scope. Existing keys are <b>not</b> deactivated — use <see cref="RotateDekAsync(string, CancellationToken)"/> for rotation.
    /// </summary>
    /// <remarks>
    /// Typically called internally by <see cref="GetActiveDekAsync(string, System.Threading.CancellationToken)"/>
    /// when no active key exists. Direct use is rare.
    /// </remarks>
    /// <param name="scope">Opaque scope identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<Dek> CreateDekAsync(string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Rotates the active DEK for the given scope: deactivates the current active key and creates a new one.
    /// </summary>
    /// <remarks>
    /// Historical payloads remain decryptable via <see cref="GetDekByKeyIdAsync(System.Guid, string, System.Threading.CancellationToken)"/>.
    /// </remarks>
    /// <param name="scope">Opaque scope identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task RotateDekAsync(string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the plaintext DEK for a specific key identifier scoped to the given partition,
    /// for decrypting historical payloads.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Multi-tenant defense.</b> Implementations <b>must</b> verify that the resolved key's
    /// <see cref="EncryptionKey.Scope"/> matches <paramref name="scope"/> before returning,
    /// and throw otherwise. Without this check, a tenant could decrypt another tenant's
    /// payloads by guessing a <see cref="System.Guid"/>.
    /// </para>
    /// <para>
    /// Cache-hit-is-sync: implementations should return a completed <see cref="ValueTask{TResult}"/>
    /// when the DEK for <paramref name="keyId"/> is already cached.
    /// </para>
    /// </remarks>
    /// <param name="keyId">Key identifier, typically stored alongside the ciphertext.</param>
    /// <param name="scope">Opaque scope identifier that must match the persisted key's scope. Defense against cross-tenant key lookup.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The plaintext DEK. Callers own the <see cref="Dek.Key"/> array and should zero it out after use.</returns>
    /// <exception cref="System.InvalidOperationException">Thrown when the key does not exist or when the key's persisted scope does not match <paramref name="scope"/>.</exception>
    public ValueTask<Dek> GetDekByKeyIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default);
}
