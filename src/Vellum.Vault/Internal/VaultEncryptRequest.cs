using System.Text.Json.Serialization;

namespace Vellum.Vault.Internal;

/// <summary>
/// Request body for <c>POST /v1/transit/encrypt/{key}</c>.
/// </summary>
/// <param name="Plaintext">Base64-encoded DEK bytes to wrap.</param>
internal sealed record VaultEncryptRequest(
    [property: JsonPropertyName("plaintext")] string Plaintext);
