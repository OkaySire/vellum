using System.Text.Json.Serialization;

namespace Vellum.Vault.Internal;

/// <summary>
/// The <c>data</c> envelope of a Vault Transit encrypt response.
/// </summary>
/// <param name="Ciphertext">The Vault-wrapped ciphertext in <c>vault:v{N}:...</c> format.</param>
internal sealed record VaultEncryptResponseData(
    [property: JsonPropertyName("ciphertext")] string? Ciphertext);
