using System.Text.Json.Serialization;

namespace Vellum.Vault.Internal;

/// <summary>
/// Request body for <c>POST /v1/transit/rewrap/{key}</c>.
/// </summary>
/// <param name="Ciphertext">The Vault-wrapped ciphertext (<c>vault:v{N}:...</c>) to re-encrypt under the latest key version.</param>
internal sealed record VaultRewrapRequest(
    [property: JsonPropertyName("ciphertext")] string Ciphertext);
