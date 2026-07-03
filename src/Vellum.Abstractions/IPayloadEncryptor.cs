namespace Vellum;

/// <summary>
/// Encrypts and decrypts binary payloads using envelope encryption backed by <see cref="IDekManager"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="IPayloadEncryptor"/> is the high-level, scope-aware API that application code should
/// use for most encryption needs. It:
/// </para>
/// <list type="bullet">
///   <item><description>Resolves the active DEK for the given scope via <see cref="IDekManager"/>.</description></item>
///   <item><description>Generates a fresh 12-byte AES-GCM nonce.</description></item>
///   <item><description>Encrypts the plaintext with AES-256-GCM.</description></item>
///   <item><description>Returns a self-contained <see cref="EncryptedPayload"/> bundling the ciphertext, nonce, wrapped DEK, and audit identifier.</description></item>
/// </list>
/// <para>
/// <b>Symmetry.</b> The encrypt and decrypt signatures are symmetric: <see cref="EncryptAsync"/>
/// takes the plaintext plus the scope and returns an <see cref="EncryptedPayload"/>;
/// <see cref="DecryptAsync"/> takes the same <see cref="EncryptedPayload"/> unchanged plus the
/// same scope. There is no intermediate DTO or hand-rolled base64 conversion.
/// </para>
/// <para>
/// <b>Scope binding.</b> Format version 2 envelopes (the default, see
/// <see cref="EncryptedPayload.ScopeBoundFormatVersion"/>) bind the ciphertext to its scope via
/// AES-GCM associated data. The scope passed to <see cref="DecryptAsync"/> must therefore match
/// the scope used at encryption time — a mismatch fails the authentication tag check. Legacy
/// format version 1 envelopes carry no binding and decrypt regardless of the scope argument.
/// </para>
/// <para>
/// <b>Binary-first.</b> The primary API operates on <see cref="ReadOnlyMemory{T}"/> and
/// <see cref="byte"/> arrays to avoid forcing a base64 round-trip on binary payloads (files,
/// protobuf, BSON, etc.). Use the string convenience extensions in
/// <see cref="PayloadEncryptorExtensions"/> when your plaintext is UTF-8 text.
/// </para>
/// <para>
/// <b>Fail closed.</b> Any error must throw. Implementations never return the plaintext unencrypted.
/// </para>
/// </remarks>
public interface IPayloadEncryptor
{
    /// <summary>
    /// Indicates whether this encryptor is configured and ready to encrypt or decrypt.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Consumers can inspect <see cref="IsEnabled"/> to implement feature-flagged encryption
    /// during a rollout: if encryption is not yet configured for a given deployment, they can
    /// skip the call rather than let it throw. When <see langword="false"/>, callers must
    /// <b>not</b> invoke <see cref="EncryptAsync"/> or <see cref="DecryptAsync"/> — both will
    /// throw.
    /// </para>
    /// <para>
    /// A default Core implementation will return <see langword="true"/> when both a
    /// <see cref="IKeyEncryptionProvider"/> and an <see cref="IEncryptionKeyStore"/> are
    /// registered in the DI container.
    /// </para>
    /// </remarks>
    public bool IsEnabled { get; }

    /// <summary>
    /// Encrypts the given plaintext bytes using the active DEK for the specified scope.
    /// </summary>
    /// <param name="plaintext">Plaintext bytes to encrypt. Any binary content is supported.</param>
    /// <param name="scope">Opaque scope identifier used to resolve the active DEK.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A self-contained <see cref="EncryptedPayload"/> bundling the ciphertext, nonce, wrapped DEK, and audit identifier.</returns>
    /// <exception cref="System.InvalidOperationException">Thrown when <see cref="IsEnabled"/> is <see langword="false"/> or the DEK cannot be resolved.</exception>
    /// <exception cref="System.OperationCanceledException">Thrown when <paramref name="cancellationToken"/> is cancelled.</exception>
    public Task<EncryptedPayload> EncryptAsync(ReadOnlyMemory<byte> plaintext, string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts a previously-encrypted payload.
    /// </summary>
    /// <param name="payload">The self-contained envelope produced by a prior call to <see cref="EncryptAsync(System.ReadOnlyMemory{byte}, string, System.Threading.CancellationToken)"/>.</param>
    /// <param name="scope">
    /// The scope the envelope was encrypted under. <b>Required</b> (non-empty) for format
    /// version 2 envelopes, which bind the ciphertext to the scope via AES-GCM associated
    /// data — a missing scope fails closed before any KEK round-trip, and a wrong scope fails
    /// the authentication tag check. Ignored for legacy format version 1 envelopes, which
    /// carry no binding and decrypt regardless of this argument.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The original plaintext bytes. Callers own this array and should zero it out if it contains sensitive data.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when the envelope format version is unsupported, when <paramref name="scope"/> is missing for a format version 2 envelope, or when the ciphertext is corrupted, tampered with, bound to a different scope, or does not match the authentication tag.</exception>
    /// <exception cref="System.InvalidOperationException">Thrown when <see cref="IsEnabled"/> is <see langword="false"/> or the wrapped DEK cannot be unwrapped.</exception>
    /// <exception cref="System.OperationCanceledException">Thrown when <paramref name="cancellationToken"/> is cancelled.</exception>
    public Task<byte[]> DecryptAsync(EncryptedPayload payload, string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns a copy of <paramref name="payload"/> whose embedded wrapped DEK
    /// (<see cref="EncryptedPayload.WrappedDek"/>) has been re-encrypted under the KEK provider's
    /// current key version via <see cref="IKeyEncryptionProvider.RewrapAsync(WrappedKey, CancellationToken)"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every persisted envelope embeds its own copy of the wrapped DEK, so retiring an old KEK
    /// version (for example, bumping Vault Transit's <c>min_decryption_version</c>) requires
    /// rewrapping each stored envelope first. Consumers iterate their own payload storage and call
    /// this method per envelope, persisting the returned copy in place of the original.
    /// </para>
    /// <para>
    /// <b>Payload untouched.</b> The plaintext DEK is unchanged by the rewrap, so the AES-GCM
    /// ciphertext stays valid: <see cref="EncryptedPayload.Ciphertext"/>,
    /// <see cref="EncryptedPayload.Nonce"/>, <see cref="EncryptedPayload.KeyId"/> and
    /// <see cref="EncryptedPayload.FormatVersion"/> are carried over verbatim — only
    /// <see cref="EncryptedPayload.WrappedDek"/> differs. The returned envelope decrypts to the
    /// same plaintext under the same scope.
    /// </para>
    /// <para>
    /// <b>Idempotent.</b> Rewrapping an envelope that is already wrapped under the current KEK
    /// version is harmless — the result simply carries a fresh ciphertext for the same version,
    /// so a partially-completed sweep can be re-run from the start.
    /// </para>
    /// <para>
    /// <b>Fail closed.</b> Any error must throw; the original envelope is never returned as if it
    /// had been rewrapped.
    /// </para>
    /// </remarks>
    /// <param name="payload">The self-contained envelope whose wrapped DEK should be rewrapped.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A copy of <paramref name="payload"/> with a freshly-rewrapped <see cref="EncryptedPayload.WrappedDek"/>.</returns>
    /// <exception cref="System.InvalidOperationException">Thrown when <see cref="IsEnabled"/> is <see langword="false"/> or the wrapped DEK cannot be rewrapped.</exception>
    /// <exception cref="System.OperationCanceledException">Thrown when <paramref name="cancellationToken"/> is cancelled.</exception>
    public Task<EncryptedPayload> RewrapPayloadAsync(EncryptedPayload payload, CancellationToken cancellationToken = default);
}
