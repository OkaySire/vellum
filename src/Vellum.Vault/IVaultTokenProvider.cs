namespace Vellum.Vault;

/// <summary>
/// Supplies the Vault auth token placed on the <c>X-Vault-Token</c> header of every Vault
/// Transit request.
/// </summary>
/// <remarks>
/// <para>
/// Implementations are registered as a <b>singleton</b> so that any token cache (see
/// <see cref="AppRoleVaultTokenProvider"/>) is shared across the transient typed
/// <see cref="HttpClient"/> instances handed out by <see cref="IHttpClientFactory"/>.
/// Implementations must therefore be thread-safe.
/// </para>
/// <para>
/// Built-in implementations: <see cref="StaticVaultTokenProvider"/> (a fixed token from
/// <see cref="VaultOptions.Token"/>) and <see cref="AppRoleVaultTokenProvider"/> (AppRole
/// login with cached, automatically re-acquired tokens). Consumers may register their own
/// implementation before calling <c>AddVaultProvider</c> to integrate other Vault auth
/// methods (Kubernetes, AWS IAM, …).
/// </para>
/// </remarks>
public interface IVaultTokenProvider
{
    /// <summary>
    /// Returns a Vault token valid for use on the <c>X-Vault-Token</c> header.
    /// </summary>
    /// <param name="cancellationToken">Cancels any in-flight token acquisition.</param>
    /// <returns>The token. Never <see langword="null"/> or empty — fail closed.</returns>
    public ValueTask<string> GetTokenAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Discards any cached token so the next <see cref="GetTokenAsync"/> call acquires a
    /// fresh one. Called by <see cref="VaultAuthenticationHandler"/> when Vault answers
    /// <c>403 Forbidden</c> — the usual signature of an expired or revoked token.
    /// </summary>
    public void InvalidateToken();
}
