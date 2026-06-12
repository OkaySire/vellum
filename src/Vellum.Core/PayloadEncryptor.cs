using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

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
/// <para>
/// <b>Scope binding (M-B).</b> When <see cref="VellumOptions.BindScopeToCiphertext"/> is
/// <see langword="true"/> (the default), <see cref="EncryptAsync"/> produces format version 2
/// envelopes whose AES-GCM associated data binds the ciphertext to its scope — see
/// <see cref="EncryptedPayload.ScopeBoundFormatVersion"/> for the exact AAD layout.
/// <see cref="DecryptAsync"/> reconstructs the same associated data from the caller-supplied
/// scope, so a scope mismatch fails the authentication tag check.
/// </para>
/// </remarks>
public sealed partial class PayloadEncryptor(
    IDekManager dekManager,
    IRandomBytesProvider randomBytes,
    IOptions<VellumOptions> options,
    ILogger<PayloadEncryptor> logger) : IPayloadEncryptor
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int DekSizeBytes = 32;

    /// <summary>
    /// Versioned label prefixed to the scope to form the format-version-2 associated data.
    /// The label domain-separates the v2 AAD from any future AAD layout, so a v3 format can
    /// never produce AAD bytes that collide with a v2 envelope's binding.
    /// </summary>
    private const string ScopeAadLabel = "vellum:aad:v2:scope:";

    private readonly IDekManager _dekManager = dekManager ?? throw new ArgumentNullException(nameof(dekManager));
    private readonly IRandomBytesProvider _randomBytes = randomBytes ?? throw new ArgumentNullException(nameof(randomBytes));
    private readonly VellumOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
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
            // H-1 symmetry (encrypt side): AesGcm accepts 16/24/32-byte keys, so a buggy
            // IDekManager (or KEK provider behind it) returning a short DEK would silently
            // downgrade new envelopes to AES-128. Pin the AES-256 contract here, mirroring
            // the decrypt-side check below, so the downgrade fails closed instead.
            if (dek.Key.Length != DekSizeBytes)
            {
                throw new CryptographicException(
                    $"Active DEK has invalid length: expected {DekSizeBytes} bytes (AES-256), got {dek.Key.Length}.");
            }

            byte[] nonce = new byte[NonceSize];
            _randomBytes.Fill(nonce);

            byte[] ciphertextWithTag = new byte[plaintext.Length + TagSize];
            Span<byte> ciphertextSpan = ciphertextWithTag.AsSpan(0, plaintext.Length);
            Span<byte> tagSpan = ciphertextWithTag.AsSpan(plaintext.Length, TagSize);

            // M-B: bind the ciphertext to its scope via AES-GCM associated data (format
            // version 2) unless the consumer explicitly opted out because the scope is not
            // available at decrypt time. A null byte[] converts to an empty span, which is
            // cryptographically identical to "no AAD" — exactly the version-1 layout.
            bool bindScope = _options.BindScopeToCiphertext;
            byte[]? associatedData = bindScope ? BuildScopeAad(scope) : null;

            using (AesGcm aesGcm = new(dek.Key, TagSize))
            {
                aesGcm.Encrypt(nonce, plaintext.Span, ciphertextSpan, tagSpan, associatedData);
            }

            LogPayloadEncrypted(_logger, scope);
            return new EncryptedPayload(
                ciphertextWithTag,
                nonce,
                dek.WrappedKey,
                dek.KeyId,
                FormatVersion: bindScope
                    ? EncryptedPayload.ScopeBoundFormatVersion
                    : EncryptedPayload.UnboundFormatVersion);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek.Key);
        }
    }

    /// <inheritdoc />
    public async Task<byte[]> DecryptAsync(
        EncryptedPayload payload,
        string scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);

        // Fail closed on unknown envelope formats BEFORE any crypto work (no DEK unwrap, no
        // KEK round-trip, no AES-GCM call). A future format may change the AAD, add key
        // commitment, or switch algorithms — interpreting its bytes under a known-version
        // layout would be undefined behavior at best and a security bug at worst.
        if (payload.FormatVersion is not (EncryptedPayload.UnboundFormatVersion or EncryptedPayload.ScopeBoundFormatVersion))
        {
            throw new CryptographicException(
                $"Unsupported envelope format version {payload.FormatVersion}: this version of Vellum only supports format versions {EncryptedPayload.UnboundFormatVersion} and {EncryptedPayload.ScopeBoundFormatVersion}.");
        }

        // M-B: a format version 2 envelope is bound to its scope — refusing a missing scope
        // here (before any unwrap / KEK round-trip) fails closed instead of burning a KEK
        // call on a decrypt that is guaranteed to fail the tag check. Version 1 envelopes
        // carry no binding, so the scope argument is deliberately not validated for them.
        bool scopeBound = payload.FormatVersion == EncryptedPayload.ScopeBoundFormatVersion;
        if (scopeBound && string.IsNullOrEmpty(scope))
        {
            throw new CryptographicException(
                "Scope is required for format version 2 envelopes: the ciphertext is bound to its scope via AES-GCM associated data and cannot be decrypted without it.");
        }

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

            // M-B: reconstruct the scope AAD for version 2 envelopes. A wrong scope yields
            // different AAD bytes and AES-GCM rejects the authentication tag — that IS the
            // cryptographic scope-binding guarantee, no additional equality check needed.
            byte[]? associatedData = scopeBound ? BuildScopeAad(scope) : null;

            using (AesGcm aesGcm = new(dek.Key, TagSize))
            {
                aesGcm.Decrypt(payload.Nonce, ciphertext, tag, plaintext, associatedData);
            }

            LogPayloadDecrypted(_logger, payload.KeyId);
            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek.Key);
        }
    }

    /// <summary>
    /// Builds the AES-GCM associated data for a format version 2 envelope:
    /// <c>UTF8("vellum:aad:v2:scope:" + scope)</c>. This is the single place the v2 AAD
    /// layout is defined — encrypt and decrypt both call it, so the two sides can never
    /// drift apart.
    /// </summary>
    private static byte[] BuildScopeAad(string scope) =>
        Encoding.UTF8.GetBytes(ScopeAadLabel + scope);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Payload encrypted for scope {Scope}")]
    private static partial void LogPayloadEncrypted(ILogger logger, string scope);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Payload decrypted with key {KeyId}")]
    private static partial void LogPayloadDecrypted(ILogger logger, Guid keyId);
}
