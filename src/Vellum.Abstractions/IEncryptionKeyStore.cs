namespace Vellum;

/// <summary>
/// Persistent storage for wrapped Data Encryption Keys, abstracted away from any specific database or ORM.
/// </summary>
/// <remarks>
/// <para>
/// Implementations back the store with EF Core, an in-memory dictionary, or any other storage engine.
/// Vellum's core logic (<see cref="IDekManager"/>) only interacts with DEKs through this interface.
/// </para>
/// <para>
/// <b>Tenant filtering.</b> Implementations built on top of EF Core <b>must</b> bypass any global
/// tenant query filters when reading keys. DEKs are infrastructure — they are not scoped by the
/// consumer's tenant filter. Failing to bypass query filters caused a production incident in the
/// upstream project (race conditions returning <see langword="null"/> for the winner of a DEK
/// creation race). See <c>tasks/lessons.md</c> L1 for details.
/// </para>
/// <para>
/// <b>Fail closed.</b> Any error must throw. Implementations must never swallow exceptions or
/// return <see langword="null"/> to mask failures.
/// </para>
/// </remarks>
public interface IEncryptionKeyStore
{
    /// <summary>
    /// Returns the currently-active key for the given scope, or <see langword="null"/> if no active key exists.
    /// </summary>
    /// <param name="scope">Opaque scope identifier. Never interpreted by Vellum.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<EncryptionKey?> GetActiveAsync(string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns a specific key by its identifier, regardless of whether it is active.
    /// </summary>
    /// <remarks>
    /// Used when decrypting historical payloads that reference a specific <see cref="EncryptionKey.KeyId"/>.
    /// </remarks>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<EncryptionKey?> GetByIdAsync(Guid keyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists a new key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Implementations must enforce that only one key per scope is active at any time —
    /// typically via a unique index on <c>(Scope, IsActive) WHERE IsActive = true</c>.
    /// </para>
    /// <para>
    /// On race conditions (two callers creating a key for the same scope concurrently),
    /// implementations should catch the unique-violation error, detach the failed entity from
    /// any tracked context, and return the winner via a subsequent <see cref="GetActiveAsync(string, CancellationToken)"/> call.
    /// </para>
    /// </remarks>
    /// <param name="key">The key to persist.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The persisted key. For race-condition handling, this may be a different key than the one passed in (the winner of the race).</returns>
    public Task<EncryptionKey> CreateAsync(EncryptionKey key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks all keys for the given scope as inactive.
    /// </summary>
    /// <remarks>
    /// Used during key rotation, immediately before creating a new active key.
    /// </remarks>
    /// <param name="scope">Opaque scope identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task DeactivateAllAsync(string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns all keys (active and historical) for the given scope, ordered from most recent to oldest.
    /// </summary>
    /// <param name="scope">Opaque scope identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<IReadOnlyList<EncryptionKey>> GetHistoricalAsync(string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the set of scopes that currently have an active key.
    /// </summary>
    /// <remarks>
    /// Used by opt-in rotation workers (see <c>Vellum.Rotation</c>) to iterate over all scopes.
    /// </remarks>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<IReadOnlyList<string>> GetActiveScopesAsync(CancellationToken cancellationToken = default);
}
