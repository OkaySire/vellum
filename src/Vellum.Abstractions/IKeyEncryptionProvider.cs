namespace Vellum;

/// <summary>
/// A pluggable Key Encryption Key (KEK) provider capable of wrapping and unwrapping Data Encryption Keys (DEKs).
/// </summary>
/// <remarks>
/// <para>
/// Implementations delegate the actual wrap/unwrap operation to a secure backend — for example,
/// HashiCorp Vault Transit, AWS KMS, Azure Key Vault, GCP KMS, or an on-host HSM.
/// </para>
/// <para>
/// <b>Fail closed.</b> Any error during wrap or unwrap must throw. Implementations must never
/// return <see langword="null"/>, silently return the plaintext, or mask provider failures.
/// </para>
/// <para>
/// <b>Thread-safety.</b> Implementations must be safe for concurrent use by multiple threads.
/// Typically they are registered as singletons in the DI container.
/// </para>
/// </remarks>
public interface IKeyEncryptionProvider
{
    /// <summary>
    /// A stable, human-readable identifier for this provider — for example, <c>"vault"</c>, <c>"aws-kms"</c>, <c>"static"</c>.
    /// </summary>
    /// <remarks>
    /// Used in diagnostics, logging, and (optionally) by the <see cref="IEncryptionKeyStore"/> to tag stored keys.
    /// </remarks>
    public string ProviderName { get; }

    /// <summary>
    /// Wraps (encrypts) a Data Encryption Key using this provider's Key Encryption Key.
    /// </summary>
    /// <param name="dek">The plaintext DEK to wrap. Typically a 256-bit AES key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The wrapped DEK as a <see cref="WrappedKey"/>.</returns>
    /// <exception cref="System.InvalidOperationException">Thrown when the provider is not configured correctly.</exception>
    /// <exception cref="System.Net.Http.HttpRequestException">Thrown when a remote provider is unreachable.</exception>
    public Task<WrappedKey> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken cancellationToken = default);

    /// <summary>
    /// Unwraps (decrypts) a previously-wrapped Data Encryption Key.
    /// </summary>
    /// <param name="wrappedKey">The wrapped DEK produced by a prior call to <see cref="WrapAsync(ReadOnlyMemory{byte}, CancellationToken)"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The plaintext DEK bytes. Callers own this array and should zero it out after use.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when the wrapped key is corrupted or tampered with.</exception>
    /// <exception cref="System.InvalidOperationException">Thrown when the provider cannot unwrap the key (for example, the KEK has been revoked).</exception>
    public Task<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default);
}
