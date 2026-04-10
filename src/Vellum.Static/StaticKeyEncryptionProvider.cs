using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Vellum.Static;

/// <summary>
/// An <see cref="IKeyEncryptionProvider"/> that wraps and unwraps Data Encryption Keys with a
/// static AES-256 Key Encryption Key loaded from configuration.
/// </summary>
/// <remarks>
/// <para>
/// <b>⚠️ DEVELOPMENT USE ONLY ⚠️</b>
/// </para>
/// <para>
/// This provider is intended for local development, unit tests, and samples. It is never safe
/// for production use: the KEK is stored in configuration, which means data encrypted with this
/// provider has exactly the same security as the config file that holds the key. A leaked config
/// file — in a repository, a CI artefact, a log line, a crash dump, or a backup — equals a
/// leaked key, which equals a complete compromise of every Data Encryption Key wrapped by it.
/// </para>
/// <para>
/// For production, use <c>Vellum.Vault</c>, <c>Vellum.AzureKeyVault</c>, <c>Vellum.AwsKms</c>,
/// or <c>Vellum.GcpKms</c>, which keep the KEK outside the application process and enforce
/// audit, rotation, and access control.
/// </para>
/// <para>
/// <b>Wrap format.</b> The provider emits ciphertexts shaped as <c>static:v1:{base64}</c>, where
/// the base64 body is the concatenation of a 12-byte random nonce, the AES-GCM ciphertext, and
/// the 16-byte authentication tag. The format is self-contained and stateless: unwrapping only
/// requires the KEK and the wrapped blob.
/// </para>
/// <para>
/// <b>Startup warning.</b> A loud warning log is emitted on the first wrap or unwrap call so
/// that production misconfiguration is impossible to miss.
/// </para>
/// </remarks>
public sealed partial class StaticKeyEncryptionProvider : IKeyEncryptionProvider
{
    internal const string CiphertextPrefix = "static:v1:";
    private const int _nonceLengthBytes = 12;
    private const int _tagLengthBytes = 16;
    private const int _keyLengthBytes = 32;

    private readonly ILogger<StaticKeyEncryptionProvider> _logger;
    private readonly StaticOptions _options;
    private int _warningEmitted;

    /// <summary>
    /// Initializes a new instance of the <see cref="StaticKeyEncryptionProvider"/> class.
    /// </summary>
    /// <param name="options">The options carrying the base64-encoded 32-byte KEK.</param>
    /// <param name="logger">The logger used to emit the mandatory development-use warning.</param>
    public StaticKeyEncryptionProvider(
        IOptions<StaticOptions> options,
        ILogger<StaticKeyEncryptionProvider> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        EnsureAesGcmTagSupport();

        _options = options.Value;
        _logger = logger;
    }

    /// <summary>
    /// H-3: on net8 the code below constructs <see cref="AesGcm"/> via the parameterless-tag
    /// overload (the explicit-tag overload did not exist on that TFM), so the tag size falls
    /// back to the BCL default. The default matches <see cref="_tagLengthBytes"/> (16 bytes)
    /// on every shipped BCL, but it is implementation-defined. This assertion runs on every
    /// instance construction (the provider is DI-singleton, so effectively once per process)
    /// to guarantee that the running BCL supports a 16-byte tag. A future BCL change that
    /// shrinks <see cref="AesGcm.TagByteSizes"/> will fail closed at startup rather than
    /// silently weaken the authentication guarantee on the net8 path. On net9+ the assertion
    /// is redundant (the explicit-tag overload pins the value) but runs anyway as defence-in-depth.
    /// </summary>
    private static void EnsureAesGcmTagSupport()
    {
        if (AesGcm.TagByteSizes.MaxSize < _tagLengthBytes)
        {
            throw new InvalidOperationException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"AesGcm.TagByteSizes.MaxSize is {AesGcm.TagByteSizes.MaxSize} but Vellum.Static requires a {_tagLengthBytes}-byte authentication tag. This BCL is not supported."));
        }
    }

    /// <inheritdoc />
    public string ProviderName => "static";

    /// <inheritdoc />
    public Task<WrappedKey> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken cancellationToken = default)
    {
        EmitDevelopmentUseWarningOnce();

        if (dek.IsEmpty)
        {
            throw new ArgumentException("DEK must not be empty.", nameof(dek));
        }

        byte[] kek = DecodeKek();
        try
        {
            byte[] nonce = new byte[_nonceLengthBytes];
            RandomNumberGenerator.Fill(nonce);

            byte[] ciphertext = new byte[dek.Length];
            byte[] tag = new byte[_tagLengthBytes];

            using (AesGcm aes = CreateAes(kek))
            {
                aes.Encrypt(nonce, dek.Span, ciphertext, tag);
            }

            byte[] blob = new byte[_nonceLengthBytes + ciphertext.Length + _tagLengthBytes];
            Buffer.BlockCopy(nonce, 0, blob, 0, _nonceLengthBytes);
            Buffer.BlockCopy(ciphertext, 0, blob, _nonceLengthBytes, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, blob, _nonceLengthBytes + ciphertext.Length, _tagLengthBytes);

            string encoded = CiphertextPrefix + Convert.ToBase64String(blob);

            LogWrapSucceeded(_logger);
            return Task.FromResult(new WrappedKey(encoded, "v1"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <inheritdoc />
    public Task<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
    {
        EmitDevelopmentUseWarningOnce();

        ArgumentNullException.ThrowIfNull(wrappedKey);

        if (string.IsNullOrEmpty(wrappedKey.Ciphertext))
        {
            throw new ArgumentException(
                $"{nameof(WrappedKey)}.{nameof(WrappedKey.Ciphertext)} must not be null or empty.",
                nameof(wrappedKey));
        }

        if (!wrappedKey.Ciphertext.StartsWith(CiphertextPrefix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{nameof(WrappedKey)}.{nameof(WrappedKey.Ciphertext)} does not start with '{CiphertextPrefix}'; this provider only unwraps static-formatted ciphertexts."));
        }

        string body = wrappedKey.Ciphertext[CiphertextPrefix.Length..];
        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(body);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("Static wrapped DEK body is not valid base64.", ex);
        }

        if (blob.Length < _nonceLengthBytes + _tagLengthBytes)
        {
            throw new InvalidOperationException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Static wrapped DEK blob is too short: expected at least {_nonceLengthBytes + _tagLengthBytes} bytes, got {blob.Length}."));
        }

        int ciphertextLength = blob.Length - _nonceLengthBytes - _tagLengthBytes;

        ReadOnlySpan<byte> nonce = blob.AsSpan(0, _nonceLengthBytes);
        ReadOnlySpan<byte> ciphertext = blob.AsSpan(_nonceLengthBytes, ciphertextLength);
        ReadOnlySpan<byte> tag = blob.AsSpan(_nonceLengthBytes + ciphertextLength, _tagLengthBytes);

        byte[] kek = DecodeKek();
        try
        {
            byte[] dek = new byte[ciphertextLength];
            using (AesGcm aes = CreateAes(kek))
            {
                // Throws CryptographicException on tag mismatch — fail closed (L6).
                aes.Decrypt(nonce, ciphertext, tag, dek);
            }

            LogUnwrapSucceeded(_logger);
            return Task.FromResult(dek);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    private byte[] DecodeKek()
    {
        // Validation has already rejected invalid base64 / wrong length at start-up, but we must
        // stay fail-closed in case a consumer bypassed the validator: every error path throws.
        byte[] kek;
        try
        {
            kek = Convert.FromBase64String(_options.Base64Key);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException(
                $"{nameof(StaticOptions)}.{nameof(StaticOptions.Base64Key)} is not valid base64.",
                ex);
        }

        if (kek.Length != _keyLengthBytes)
        {
            int actualLength = kek.Length;
            CryptographicOperations.ZeroMemory(kek);
            throw new InvalidOperationException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{nameof(StaticOptions)}.{nameof(StaticOptions.Base64Key)} must decode to {_keyLengthBytes} bytes; got {actualLength}."));
        }

        return kek;
    }

    private static AesGcm CreateAes(byte[] kek)
    {
#if NET8_0
#pragma warning disable SYSLIB0053 // AesGcm(byte[]) is obsolete on net9+ but the only ctor on net8.
        return new AesGcm(kek);
#pragma warning restore SYSLIB0053
#else
        return new AesGcm(kek, _tagLengthBytes);
#endif
    }

    private void EmitDevelopmentUseWarningOnce()
    {
        // Interlocked so that the very first concurrent caller wins and only one warning is
        // emitted per provider instance. The instance itself is singleton-scoped in DI, so this
        // produces one warning per process.
        if (Interlocked.CompareExchange(ref _warningEmitted, 1, 0) == 0)
        {
            LogDevelopmentUseWarning(_logger);
        }
    }

    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Warning,
        Message = "\u26a0 Vellum.Static KEK provider active \u2014 DEVELOPMENT USE ONLY. Never use this provider in production. Data encrypted with the static KEK has the same security as the config source it came from.")]
    private static partial void LogDevelopmentUseWarning(ILogger logger);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Debug,
        Message = "Vellum.Static wrap succeeded.")]
    private static partial void LogWrapSucceeded(ILogger logger);

    [LoggerMessage(
        EventId = 3,
        Level = LogLevel.Debug,
        Message = "Vellum.Static unwrap succeeded.")]
    private static partial void LogUnwrapSucceeded(ILogger logger);
}
