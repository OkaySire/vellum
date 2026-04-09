using System.Text.Json.Serialization;

namespace Vellum.Vault.Internal;

/// <summary>
/// The <c>data</c> envelope of a Vault Transit decrypt response.
/// </summary>
/// <param name="Plaintext">The base64-encoded plaintext DEK bytes.</param>
internal sealed record VaultDecryptResponseData(
    [property: JsonPropertyName("plaintext")] string? Plaintext);
