using System.Text;

namespace Vellum;

/// <summary>
/// String convenience extensions over <see cref="IPayloadEncryptor"/> for callers whose
/// plaintext is UTF-8 text rather than raw binary.
/// </summary>
/// <remarks>
/// <para>
/// These helpers are pure sugar: they UTF-8 encode the input string, delegate to the binary
/// <see cref="IPayloadEncryptor.EncryptAsync(System.ReadOnlyMemory{byte}, string, System.Threading.CancellationToken)"/>,
/// and UTF-8 decode the result on the decrypt side.
/// </para>
/// <para>
/// Binary-first payloads (files, protobuf, BSON, etc.) should call the underlying
/// <see cref="IPayloadEncryptor"/> methods directly to avoid a wasteful UTF-8 round-trip.
/// </para>
/// </remarks>
public static class PayloadEncryptorExtensions
{
    /// <summary>
    /// Encrypts a UTF-8 string plaintext.
    /// </summary>
    /// <param name="encryptor">The encryptor instance.</param>
    /// <param name="plaintext">The plaintext string. Encoded as UTF-8 before encryption.</param>
    /// <param name="scope">Opaque scope identifier used to resolve the active DEK.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A self-contained <see cref="EncryptedPayload"/>.</returns>
    /// <exception cref="System.ArgumentNullException">Thrown when <paramref name="encryptor"/> or <paramref name="plaintext"/> is <see langword="null"/>.</exception>
    public static Task<EncryptedPayload> EncryptStringAsync(
        this IPayloadEncryptor encryptor,
        string plaintext,
        string scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(encryptor);
        ArgumentNullException.ThrowIfNull(plaintext);

        byte[] bytes = Encoding.UTF8.GetBytes(plaintext);
        return encryptor.EncryptAsync(bytes, scope, cancellationToken);
    }

    /// <summary>
    /// Decrypts a previously-encrypted envelope and returns the plaintext as a UTF-8 string.
    /// </summary>
    /// <param name="encryptor">The encryptor instance.</param>
    /// <param name="payload">The self-contained envelope.</param>
    /// <param name="scope">The scope the envelope was encrypted under. Required (non-empty) for format version 2 envelopes; ignored for legacy version 1 envelopes. See <see cref="IPayloadEncryptor.DecryptAsync(EncryptedPayload, string, System.Threading.CancellationToken)"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The original plaintext string (UTF-8 decoded).</returns>
    /// <exception cref="System.ArgumentNullException">Thrown when <paramref name="encryptor"/> or <paramref name="payload"/> is <see langword="null"/>.</exception>
    public static async Task<string> DecryptStringAsync(
        this IPayloadEncryptor encryptor,
        EncryptedPayload payload,
        string scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(encryptor);
        ArgumentNullException.ThrowIfNull(payload);

        byte[] plaintextBytes = await encryptor.DecryptAsync(payload, scope, cancellationToken).ConfigureAwait(false);
        return Encoding.UTF8.GetString(plaintextBytes);
    }
}
