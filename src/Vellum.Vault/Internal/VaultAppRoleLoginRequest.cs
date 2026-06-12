using System.Text.Json.Serialization;

namespace Vellum.Vault.Internal;

/// <summary>
/// Request body for <c>POST /v1/auth/{mount}/login</c> (AppRole auth method).
/// </summary>
/// <param name="RoleId">The AppRole role id. Sensitive — never logged.</param>
/// <param name="SecretId">The AppRole secret id. <b>Secret</b> — never logged.</param>
internal sealed record VaultAppRoleLoginRequest(
    [property: JsonPropertyName("role_id")] string RoleId,
    [property: JsonPropertyName("secret_id")] string SecretId);
