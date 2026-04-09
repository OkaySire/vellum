using System.Diagnostics.CodeAnalysis;

namespace Vellum;

/// <summary>
/// A Data Encryption Key (DEK) in plaintext form, alongside its identifier.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Dek"/> is the single return type used for both the currently-active DEK
/// (<see cref="IDekManager.GetActiveDekAsync(string, System.Threading.CancellationToken)"/>)
/// and historical DEKs looked up by identifier
/// (<see cref="IDekManager.GetDekByKeyIdAsync(System.Guid, string, System.Threading.CancellationToken)"/>).
/// </para>
/// <para>
/// <b>Memory hygiene.</b> The <see cref="Key"/> array contains sensitive plaintext key material.
/// Callers should treat it as short-lived and zero it out after use
/// (for example, via <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory(System.Span{byte})"/>).
/// </para>
/// <para>
/// Cache implementations returning <see cref="Dek"/> instances must clone the key bytes
/// before returning them so that callers can safely zero their copy without corrupting the cache.
/// See <c>tasks/lessons.md</c> L3 for the rationale.
/// </para>
/// </remarks>
/// <param name="Key">Plaintext DEK bytes (typically a 256-bit AES key). Callers own this array and should zero it after use.</param>
/// <param name="KeyId">Identifier of the key, used to locate the corresponding <see cref="EncryptionKey"/> record when decrypting.</param>
[SuppressMessage(
    "Performance",
    "CA1819:Properties should not return arrays",
    Justification = "Dek carries mutable key material by design so that callers can zero memory after use. ReadOnlyMemory<byte> would prevent callers from scrubbing the underlying storage.")]
public sealed record Dek(byte[] Key, Guid KeyId);
