namespace Vellum;

/// <summary>
/// A fully-sealed encrypted payload that can be persisted and later decrypted without access to external state beyond the configured <see cref="IKeyEncryptionProvider"/> and <see cref="IEncryptionKeyStore"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="EncryptedPayload"/> is the canonical "envelope" returned by high-level encryption APIs.
/// It bundles everything needed to decrypt the payload later:
/// </para>
/// <list type="bullet">
///   <item><description>The AES-GCM ciphertext (base64-encoded).</description></item>
///   <item><description>The AES-GCM nonce (base64-encoded).</description></item>
///   <item><description>The KEK-wrapped DEK or a reference to it via <see cref="KeyId"/>.</description></item>
///   <item><description>The KEK provider version used at encryption time.</description></item>
/// </list>
/// </remarks>
/// <param name="CiphertextBase64">Base64-encoded AES-GCM ciphertext. The authentication tag is appended to the ciphertext per .NET's <see cref="System.Security.Cryptography.AesGcm"/> convention.</param>
/// <param name="NonceBase64">Base64-encoded AES-GCM nonce. Must be 12 bytes (96 bits). Unique per (key, plaintext) pair — never reused.</param>
/// <param name="KeyId">Identifier of the <see cref="EncryptionKey"/> used to derive the DEK. Used to look up the wrapped DEK via <see cref="IEncryptionKeyStore"/>.</param>
/// <param name="ProviderVersion">Version of the KEK provider at the time of encryption. Retained for audit and rotation tracking.</param>
public sealed record EncryptedPayload(
    string CiphertextBase64,
    string NonceBase64,
    Guid KeyId,
    int ProviderVersion);
