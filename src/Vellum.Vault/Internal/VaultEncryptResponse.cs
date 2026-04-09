using System.Text.Json.Serialization;

namespace Vellum.Vault.Internal;

/// <summary>
/// Response body for <c>POST /v1/transit/encrypt/{key}</c>.
/// </summary>
/// <param name="Data">The <c>data</c> envelope returned by Vault.</param>
internal sealed record VaultEncryptResponse(
    [property: JsonPropertyName("data")] VaultEncryptResponseData? Data);
