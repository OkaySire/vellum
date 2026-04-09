namespace Vellum;

/// <summary>
/// Encrypts and decrypts string payloads using envelope encryption backed by <see cref="IDekManager"/>.
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
///   <item><description>Returns a <see cref="PayloadEncryptionResult"/> containing the ciphertext, nonce, and key identifier for later decryption.</description></item>
/// </list>
/// <para>
/// <b>Fail closed.</b> Any error must throw. Implementations never return the plaintext unencrypted.
/// </para>
/// </remarks>
public interface IPayloadEncryptor
{
    /// <summary>
    /// Encrypts the given plaintext string using the active DEK for the specified scope.
    /// </summary>
    /// <param name="plaintext">Plaintext to encrypt. Encoded as UTF-8 before encryption.</param>
    /// <param name="scope">Opaque scope identifier used to resolve the active DEK.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="PayloadEncryptionResult"/> containing the ciphertext, nonce, and key identifier.</returns>
    public Task<PayloadEncryptionResult> EncryptAsync(string plaintext, string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts a previously-encrypted payload.
    /// </summary>
    /// <param name="ciphertextBase64">Base64-encoded ciphertext (with appended AES-GCM authentication tag).</param>
    /// <param name="nonce">The 12-byte AES-GCM nonce used at encryption time.</param>
    /// <param name="keyId">Identifier of the DEK used at encryption time.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The original UTF-8 plaintext string.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when the ciphertext is corrupted, tampered with, or does not match the authentication tag.</exception>
    /// <exception cref="System.InvalidOperationException">Thrown when the <paramref name="keyId"/> cannot be resolved.</exception>
    public Task<string> DecryptAsync(string ciphertextBase64, byte[] nonce, Guid keyId, CancellationToken cancellationToken = default);
}
