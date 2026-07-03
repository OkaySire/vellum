using System.Text.Json.Serialization;

namespace Vellum.Vault.Internal;

/// <summary>
/// The <c>data</c> envelope of a Vault Transit rewrap response.
/// </summary>
/// <param name="Ciphertext">The re-encrypted ciphertext in <c>vault:v{N}:...</c> format, wrapped under the latest key version.</param>
internal sealed record VaultRewrapResponseData(
    [property: JsonPropertyName("ciphertext")] string? Ciphertext);
