using System.Text.Json.Serialization;

namespace Vellum.Vault.Internal;

/// <summary>
/// The <c>auth</c> envelope of a Vault AppRole login response.
/// </summary>
/// <param name="ClientToken">The issued Vault token. <b>Secret</b> — never logged.</param>
/// <param name="LeaseDuration">
/// Token lifetime in seconds. <c>0</c> means the token never expires (Vault semantics).
/// </param>
/// <param name="Renewable">
/// Whether the token supports <c>renew-self</c>. Ignored by
/// <see cref="AppRoleVaultTokenProvider"/>, which re-logs-in instead of renewing — see its
/// class remarks for the rationale.
/// </param>
internal sealed record VaultAppRoleLoginAuth(
    [property: JsonPropertyName("client_token")] string? ClientToken,
    [property: JsonPropertyName("lease_duration")] long LeaseDuration,
    [property: JsonPropertyName("renewable")] bool Renewable);
