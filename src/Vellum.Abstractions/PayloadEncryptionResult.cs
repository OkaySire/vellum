using System.Diagnostics.CodeAnalysis;

namespace Vellum;

/// <summary>
/// Low-level result returned by <see cref="IPayloadEncryptor.EncryptAsync(string, string, System.Threading.CancellationToken)"/>.
/// </summary>
/// <remarks>
/// <para>
/// Unlike <see cref="EncryptedPayload"/>, this record returns the raw nonce as <c>byte[]</c>
/// for callers that need to store it in a binary column rather than re-encoding base64.
/// </para>
/// </remarks>
/// <param name="CiphertextBase64">Base64-encoded AES-GCM ciphertext (with appended auth tag).</param>
/// <param name="Nonce">Raw 12-byte AES-GCM nonce. Must be stored alongside the ciphertext for decryption.</param>
/// <param name="KeyId">Identifier of the <see cref="EncryptionKey"/> used to derive the DEK.</param>
[SuppressMessage(
    "Performance",
    "CA1819:Properties should not return arrays",
    Justification = "Nonce is a raw 12-byte AES-GCM IV and intentionally exposed as byte[] so callers can persist it directly in binary storage columns without re-encoding.")]
public sealed record PayloadEncryptionResult(
    string CiphertextBase64,
    byte[] Nonce,
    Guid KeyId);
