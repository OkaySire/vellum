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
/// </remarks>
public interface IDekManager
{
    /// <summary>
    /// Returns the active DEK for the given scope, creating one if none exists.
    /// </summary>
    /// <param name="scope">Opaque scope identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<ActiveDek> GetActiveDekAsync(string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new DEK for the given scope. Existing keys are <b>not</b> deactivated — use <see cref="RotateDekAsync(string, CancellationToken)"/> for rotation.
    /// </summary>
    /// <remarks>
    /// Typically called internally by <see cref="GetActiveDekAsync(string, CancellationToken)"/>
    /// when no active key exists. Direct use is rare.
    /// </remarks>
    /// <param name="scope">Opaque scope identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<ActiveDek> CreateDekAsync(string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Rotates the active DEK for the given scope: deactivates the current active key and creates a new one.
    /// </summary>
    /// <remarks>
    /// Historical payloads remain decryptable via <see cref="GetDekByKeyIdAsync(Guid, CancellationToken)"/>.
    /// </remarks>
    /// <param name="scope">Opaque scope identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task RotateDekAsync(string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the plaintext DEK for a specific key identifier, for decrypting historical payloads.
    /// </summary>
    /// <param name="keyId">Key identifier, typically stored alongside the ciphertext.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The plaintext DEK bytes. Callers own this array and should zero it out after use.</returns>
    /// <exception cref="System.InvalidOperationException">Thrown when the key does not exist.</exception>
    public Task<byte[]> GetDekByKeyIdAsync(Guid keyId, CancellationToken cancellationToken = default);
}
