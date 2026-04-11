using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Vellum;

/// <summary>
/// Default <see cref="IPayloadEncryptor"/> implementation built on AES-256-GCM and envelope
/// encryption. Encryption resolves the active DEK for the given scope via
/// <see cref="IDekManager"/>; decryption unwraps the DEK embedded in the self-contained
/// <see cref="EncryptedPayload"/> via <see cref="IKeyEncryptionProvider"/> alone.
/// </summary>
/// <remarks>
/// <para>
/// <b>Self-contained decryption.</b> Because <see cref="EncryptedPayload"/> bundles the
/// <see cref="WrappedKey"/> used to wrap the DEK, decryption requires only the KEK provider
/// and has no round-trip to <see cref="IEncryptionKeyStore"/>. This matches the design of the
/// AWS Encryption SDK and Google Tink.
/// </para>
/// <para>
/// <b>AES-GCM layout.</b> The <see cref="EncryptedPayload.Ciphertext"/> field stores the raw
/// ciphertext followed by the 16-byte authentication tag, matching .NET's <see cref="AesGcm"/>
/// convention.
/// </para>
/// <para>
/// <b>Memory hygiene.</b> Plaintext DEK bytes returned by <see cref="IDekManager"/> or
/// <see cref="IKeyEncryptionProvider.UnwrapAsync"/> are zeroed in a <c>finally</c> block after
/// the AES-GCM operation completes, whether it succeeds or throws.
/// </para>
/// </remarks>
public sealed partial class PayloadEncryptor(
    IDekManager dekManager,
    IRandomBytesProvider randomBytes,
    ILogger<PayloadEncryptor> logger) : IPayloadEncryptor
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int DekSizeBytes = 32;

    private readonly IDekManager _dekManager = dekManager ?? throw new ArgumentNullException(nameof(dekManager));
    private readonly IRandomBytesProvider _randomBytes = randomBytes ?? throw new ArgumentNullException(nameof(randomBytes));
    private readonly ILogger<PayloadEncryptor> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    /// <inheritdoc />
    /// <remarks>
    /// The default implementation is always enabled once the dependencies resolve through DI.
    /// Consumers that want a feature-flagged rollout should wrap this type behind their own
    /// guard, or register an alternative <see cref="IPayloadEncryptor"/> implementation whose
    /// <see cref="IsEnabled"/> is false.
    /// </remarks>
    public bool IsEnabled => true;

    /// <inheritdoc />
    public async Task<EncryptedPayload> EncryptAsync(
        ReadOnlyMemory<byte> plaintext,
        string scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);

        Dek dek = await _dekManager.GetActiveDekAsync(scope, cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] nonce = new byte[NonceSize];
            _randomBytes.Fill(nonce);

            byte[] ciphertextWithTag = new byte[plaintext.Length + TagSize];
            Span<byte> ciphertextSpan = ciphertextWithTag.AsSpan(0, plaintext.Length);
            Span<byte> tagSpan = ciphertextWithTag.AsSpan(plaintext.Length, TagSize);

            using (AesGcm aesGcm = new(dek.Key, TagSize))
            {
                aesGcm.Encrypt(nonce, plaintext.Span, ciphertextSpan, tagSpan);
            }

            LogPayloadEncrypted(_logger, scope);
            return new EncryptedPayload(ciphertextWithTag, nonce, dek.WrappedKey, dek.KeyId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek.Key);
        }
    }

    /// <inheritdoc />
    public async Task<byte[]> DecryptAsync(
        EncryptedPayload payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);

        if (payload.Nonce.Length != NonceSize)
        {
            throw new CryptographicException(
                $"Invalid nonce length: expected {NonceSize} bytes, got {payload.Nonce.Length}.");
        }

        if (payload.Ciphertext.Length < TagSize)
        {
            throw new CryptographicException(
                $"Ciphertext too short to contain a {TagSize}-byte authentication tag.");
        }

        // Issue #6: route through IDekManager.GetDekByWrappedKeyAsync instead of calling
        // IKeyEncryptionProvider.UnwrapAsync directly. The manager caches unwrapped DEKs
        // keyed by a SHA-256 hash of the wrapped ciphertext so read-heavy workloads avoid
        // a Vault / KMS round-trip on every decrypt. The cache-hit path is synchronous
        // (ValueTask) and allocation-free aside from the required Dek clone.
        Dek dek = await _dekManager.GetDekByWrappedKeyAsync(payload.WrappedDek, cancellationToken).ConfigureAwait(false);
        try
        {
            // H-1 symmetry: the slow path in DekManager already enforces the AES-256 length
            // contract on unwrap, but pin it again here so that a future refactor of the
            // cache (or a cache-poisoning test asserting the fail-closed behaviour) cannot
            // silently downgrade the cipher strength.
            if (dek.Key.Length != DekSizeBytes)
            {
                throw new CryptographicException(
                    $"Unwrapped DEK has invalid length: expected {DekSizeBytes} bytes (AES-256), got {dek.Key.Length}.");
            }

            int ciphertextLength = payload.Ciphertext.Length - TagSize;
            ReadOnlySpan<byte> ciphertext = payload.Ciphertext.AsSpan(0, ciphertextLength);
            ReadOnlySpan<byte> tag = payload.Ciphertext.AsSpan(ciphertextLength, TagSize);

            byte[] plaintext = new byte[ciphertextLength];

            using (AesGcm aesGcm = new(dek.Key, TagSize))
            {
                aesGcm.Decrypt(payload.Nonce, ciphertext, tag, plaintext);
            }

            LogPayloadDecrypted(_logger, payload.KeyId);
            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek.Key);
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Payload encrypted for scope {Scope}")]
    private static partial void LogPayloadEncrypted(ILogger logger, string scope);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Payload decrypted with key {KeyId}")]
    private static partial void LogPayloadDecrypted(ILogger logger, Guid keyId);
}
