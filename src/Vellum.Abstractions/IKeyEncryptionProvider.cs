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

    /// <summary>
    /// Re-encrypts (rewraps) a previously-wrapped Data Encryption Key under the provider's
    /// <b>current</b> Key Encryption Key version.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Rewrapping is the building block for retiring old KEK versions: after the KEK is rotated,
    /// every persisted wrapped DEK (key-store rows and the <see cref="EncryptedPayload.WrappedDek"/>
    /// embedded in every envelope) still references the old version. Rewrapping refreshes the
    /// wrapping without touching the plaintext payload — the DEK itself is unchanged, so existing
    /// AES-GCM ciphertexts remain valid.
    /// </para>
    /// <para>
    /// <b>Plaintext confinement.</b> The plaintext DEK is never exposed to the caller. Backends
    /// with a native rewrap operation (for example, Vault Transit's <c>/rewrap</c> endpoint)
    /// perform the re-encryption entirely inside the backend; where no native operation exists,
    /// the implementation must unwrap and rewrap internally without letting the plaintext escape
    /// the provider, zeroing the intermediate bytes when done.
    /// </para>
    /// <para>
    /// <b>Fail closed.</b> Any error must throw. Implementations must never return the original
    /// <paramref name="wrappedKey"/> unchanged to mask a failure.
    /// </para>
    /// </remarks>
    /// <param name="wrappedKey">The wrapped DEK produced by a prior call to <see cref="WrapAsync(ReadOnlyMemory{byte}, CancellationToken)"/> (possibly under an older KEK version).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A new <see cref="WrappedKey"/> wrapping the same DEK under the current KEK version, with <see cref="WrappedKey.ProviderVersion"/> updated accordingly.</returns>
    /// <exception cref="System.InvalidOperationException">Thrown when the provider cannot rewrap the key (for example, the original KEK version has been revoked).</exception>
    /// <exception cref="System.Net.Http.HttpRequestException">Thrown when a remote provider is unreachable.</exception>
    public Task<WrappedKey> RewrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default);
}
