using System.Text.Json.Serialization;

namespace Vellum.Vault.Internal;

/// <summary>
/// Response body for <c>POST /v1/auth/{mount}/login</c> (AppRole auth method).
/// </summary>
/// <param name="Auth">The <c>auth</c> envelope returned by Vault.</param>
internal sealed record VaultAppRoleLoginResponse(
    [property: JsonPropertyName("auth")] VaultAppRoleLoginAuth? Auth);
