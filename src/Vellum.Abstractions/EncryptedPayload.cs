using System.Diagnostics.CodeAnalysis;

namespace Vellum;

/// <summary>
/// A fully self-contained envelope bundling everything needed to decrypt a payload.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="EncryptedPayload"/> is the canonical envelope returned by
/// <see cref="IPayloadEncryptor.EncryptAsync(System.ReadOnlyMemory{byte}, string, System.Threading.CancellationToken)"/>
/// and accepted by
/// <see cref="IPayloadEncryptor.DecryptAsync(EncryptedPayload, System.Threading.CancellationToken)"/>.
/// </para>
/// <para>
/// <b>Self-contained.</b> The envelope carries the wrapped DEK (<see cref="WrappedDek"/>) embedded
/// directly. Decryption requires <i>only</i> the configured <see cref="IKeyEncryptionProvider"/>
/// plus the fields of this record — it does <b>not</b> require a round-trip to
/// <see cref="IEncryptionKeyStore"/>. This matches the design of the AWS Encryption SDK and
/// Google Tink: a consumer that persists an envelope stores it complete in a single row and
/// decrypts without any database lookup.
/// </para>
/// <para>
/// <b>Portability.</b> Because the envelope is self-contained, it can be moved between systems
/// (for example, sent by email or copied across environments) and decrypted anywhere the same
/// KEK provider is configured.
/// </para>
/// <para>
/// <b>Audit only.</b> <see cref="KeyId"/> is retained for audit and rotation tracking (so you
/// can answer "which DEK was used to encrypt this payload?") but is <b>not</b> required for
/// decryption. The <see cref="WrappedDek"/> is the sole source of truth at decrypt time.
/// </para>
/// <para>
/// <b>Value equality.</b> This record overrides <see cref="Equals(EncryptedPayload)"/> and
/// <see cref="GetHashCode"/> to provide structural equality over the <see cref="Ciphertext"/>
/// and <see cref="Nonce"/> byte arrays (rather than reference equality).
/// </para>
/// <para>
/// <b>Format versioning (crypto agility).</b> <see cref="FormatVersion"/> identifies the wire
/// format of this envelope so it can evolve without guessing — future versions may add
/// associated data (AAD), key commitment, or change the cipher/algorithm. Consumers that
/// persist envelopes field-by-field <b>must</b> persist <see cref="FormatVersion"/> alongside
/// the other fields and restore it verbatim. Unknown or unsupported versions fail closed at
/// decrypt time: <see cref="IPayloadEncryptor.DecryptAsync(EncryptedPayload, System.Threading.CancellationToken)"/>
/// throws rather than attempting to interpret bytes under the wrong format. The parameter is
/// the <i>last</i> positional parameter and defaults to <see cref="CurrentFormatVersion"/> so
/// that envelopes persisted by pre-versioning consumers (which have no stored version) can be
/// reconstructed with the original four positional arguments and continue to decrypt.
/// </para>
/// </remarks>
/// <param name="Ciphertext">Raw AES-GCM ciphertext bytes. The authentication tag is appended to the ciphertext per .NET's <see cref="System.Security.Cryptography.AesGcm"/> convention.</param>
/// <param name="Nonce">Raw AES-GCM nonce bytes. Must be 12 bytes (96 bits). Unique per (key, plaintext) pair — never reused.</param>
/// <param name="WrappedDek">The KEK-wrapped DEK used to encrypt this payload. The envelope is self-contained — decrypting needs only this field plus the configured <see cref="IKeyEncryptionProvider"/>.</param>
/// <param name="KeyId">Identifier of the <see cref="EncryptionKey"/> that was used at encryption time. Retained for audit and rotation tracking only; <b>not</b> required for decryption.</param>
/// <param name="FormatVersion">Envelope wire-format version. Defaults to <see cref="CurrentFormatVersion"/> (the only valid version today). Consumers <b>must</b> persist this field; decryption rejects unknown versions (fail closed).</param>
[SuppressMessage(
    "Performance",
    "CA1819:Properties should not return arrays",
    Justification = "Ciphertext and Nonce are raw binary payloads. Exposing them as byte[] lets callers persist them directly in binary storage columns without re-encoding to base64. Structural equality is provided by the custom Equals/GetHashCode overrides below.")]
public sealed record EncryptedPayload(
    byte[] Ciphertext,
    byte[] Nonce,
    WrappedKey WrappedDek,
    Guid KeyId,
    int FormatVersion = EncryptedPayload.CurrentFormatVersion)
{
    /// <summary>
    /// The envelope wire-format version produced by the current version of Vellum.
    /// </summary>
    /// <remarks>
    /// Version <c>1</c> means: AES-256-GCM, 12-byte nonce, 16-byte authentication tag appended
    /// to the ciphertext, no associated data (AAD), DEK wrapped by the configured
    /// <see cref="IKeyEncryptionProvider"/>. Any future change to this layout (AAD, key
    /// commitment, algorithm) bumps the version so old envelopes remain unambiguously decodable.
    /// </remarks>
    public const int CurrentFormatVersion = 1;

    /// <summary>
    /// Structural equality over all fields, including content-based comparison of the
    /// <see cref="Ciphertext"/> and <see cref="Nonce"/> byte arrays.
    /// </summary>
    public bool Equals(EncryptedPayload? other)
    {
        if (other is null)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        return FormatVersion == other.FormatVersion
            && KeyId == other.KeyId
            && WrappedDek == other.WrappedDek
            && Ciphertext.AsSpan().SequenceEqual(other.Ciphertext)
            && Nonce.AsSpan().SequenceEqual(other.Nonce);
    }

    /// <summary>
    /// Structural hash code consistent with <see cref="Equals(EncryptedPayload)"/>.
    /// </summary>
    public override int GetHashCode()
    {
        HashCode hash = default;
        hash.Add(FormatVersion);
        hash.Add(KeyId);
        hash.Add(WrappedDek);
        hash.AddBytes(Ciphertext);
        hash.AddBytes(Nonce);
        return hash.ToHashCode();
    }

    /// <summary>
    /// M-1: returns a fixed safe summary that never exposes the raw bytes of the
    /// ciphertext, nonce, or the wrapped DEK ciphertext. A consumer that naively logs an
    /// envelope ends up with a short, audit-friendly string rather than a multi-line dump
    /// of record fields generated by the compiler.
    /// </summary>
    public override string ToString() =>
        $"EncryptedPayload {{ FormatVersion = {FormatVersion}, KeyId = {KeyId}, CiphertextLength = {Ciphertext.Length}, NonceLength = {Nonce.Length} }}";
}
