using System.Text.Json.Serialization;

namespace Vellum.Vault.Internal;

/// <summary>
/// Request body for <c>POST /v1/{mount}/decrypt/{key}</c>.
/// </summary>
/// <param name="Ciphertext">The full Vault-wrapped ciphertext in <c>vault:v{N}:...</c> format.</param>
internal sealed record VaultDecryptRequest(
    [property: JsonPropertyName("ciphertext")] string Ciphertext);
