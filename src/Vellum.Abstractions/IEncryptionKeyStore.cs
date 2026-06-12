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
    /// Returns a specific key by its identifier and scope, regardless of whether it is active.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used when decrypting historical payloads that reference a specific <see cref="EncryptionKey.KeyId"/>.
    /// </para>
    /// <para>
    /// <b>Multi-tenant defense.</b> Implementations <b>must</b> verify that the resolved key's
    /// <see cref="EncryptionKey.Scope"/> matches <paramref name="scope"/> and return
    /// <see langword="null"/> (or throw) on mismatch. Without this check, a tenant could
    /// access another tenant's wrapped DEK by guessing a <see cref="System.Guid"/>.
    /// </para>
    /// </remarks>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="scope">Opaque scope identifier that must match the persisted key's scope.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<EncryptionKey?> GetByIdAsync(Guid keyId, string scope, CancellationToken cancellationToken = default);

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
    /// <b>Not suitable for rotation on its own.</b> Deactivating and then creating in two separate
    /// calls opens a window during which the scope has zero active keys — if the process crashes or
    /// the KEK provider fails between the two calls, all encrypt operations for the scope fail until
    /// a new key is created. Use <see cref="RotateAsync(EncryptionKey, CancellationToken)"/> for
    /// rotation; this method remains for administrative revocation scenarios where "no active key"
    /// is the intended end state.
    /// </remarks>
    /// <param name="scope">Opaque scope identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task DeactivateAllAsync(string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically deactivates all currently-active keys for <see cref="EncryptionKey.Scope"/> of
    /// <paramref name="newKey"/> <b>and</b> inserts <paramref name="newKey"/> as the new active key,
    /// in a single transaction.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Atomicity.</b> The deactivation of the old keys and the insertion of the new key must
    /// commit together or not at all. On failure nothing changes: the previously-active key stays
    /// active and the scope is never observed with zero active keys. This is the fail-safe
    /// foundation for DEK rotation — see the production incident where a two-step
    /// deactivate-then-create rotation left scopes without any active DEK when the KEK provider
    /// failed mid-rotation.
    /// </para>
    /// <para>
    /// <b>Race handling.</b> If a concurrent rotation commits first and the insertion of
    /// <paramref name="newKey"/> trips the one-active-key-per-scope unique constraint,
    /// implementations should return the concurrent winner (the key that is now active for the
    /// scope) instead of throwing, mirroring the <see cref="CreateAsync(EncryptionKey, CancellationToken)"/>
    /// contract. If the failure is <b>not</b> a rotation race (no fresh winner can be identified),
    /// implementations must throw — never silently leave the rotation half-applied.
    /// </para>
    /// <para>
    /// <paramref name="newKey"/> must carry <see cref="EncryptionKey.IsActive"/> =
    /// <see langword="true"/>; implementations reject an inactive key fail-closed because inserting
    /// it would end the transaction with zero active keys for the scope.
    /// </para>
    /// </remarks>
    /// <param name="newKey">The new active key to install. <see cref="EncryptionKey.IsActive"/> must be <see langword="true"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The persisted active key: <paramref name="newKey"/> itself when this call won, or the
    /// concurrent winner when another rotation raced ahead.
    /// </returns>
    public Task<EncryptionKey> RotateAsync(EncryptionKey newKey, CancellationToken cancellationToken = default);

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
