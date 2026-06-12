namespace Vellum.Vault;

/// <summary>
/// The Vault authentication method used to obtain the token sent on the
/// <c>X-Vault-Token</c> header.
/// </summary>
public enum VaultAuthMethod
{
    /// <summary>
    /// A fixed, pre-issued token supplied via <see cref="VaultOptions.Token"/>.
    /// </summary>
    /// <remarks>
    /// Simple, but operationally fragile: a periodic token that expires causes a silent
    /// outage because Vellum has no way to mint a replacement. Prefer <see cref="AppRole"/>
    /// for production deployments.
    /// </remarks>
    Token = 0,

    /// <summary>
    /// AppRole login (<c>POST /v1/auth/{mount}/login</c>) using
    /// <see cref="VaultOptions.RoleId"/> and <see cref="VaultOptions.SecretId"/>. Tokens are
    /// cached and re-acquired automatically before they expire — see
    /// <see cref="AppRoleVaultTokenProvider"/>.
    /// </summary>
    AppRole = 1,
}
