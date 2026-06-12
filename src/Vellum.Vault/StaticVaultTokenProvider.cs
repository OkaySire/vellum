using Microsoft.Extensions.Options;

namespace Vellum.Vault;

/// <summary>
/// An <see cref="IVaultTokenProvider"/> that always returns the fixed token configured in
/// <see cref="VaultOptions.Token"/>. This is the provider used when
/// <see cref="VaultOptions.AuthMethod"/> is <see cref="VaultAuthMethod.Token"/>.
/// </summary>
/// <remarks>
/// <see cref="InvalidateToken"/> is a no-op: a static token cannot be re-acquired. When the
/// token expires or is revoked, every Vault request fails with <c>403 Forbidden</c> until the
/// application is reconfigured and restarted. <see cref="VaultAuthenticationHandler"/> detects
/// that the "fresh" token is identical to the one that just failed and propagates the original
/// 403 without a useless retry.
/// </remarks>
public sealed class StaticVaultTokenProvider(IOptions<VaultOptions> options) : IVaultTokenProvider
{
    private readonly string _token = (options ?? throw new ArgumentNullException(nameof(options))).Value.Token;

    /// <inheritdoc />
    public ValueTask<string> GetTokenAsync(CancellationToken cancellationToken) => new(_token);

    /// <inheritdoc />
    /// <remarks>No-op — a static token has no re-acquisition path.</remarks>
    public void InvalidateToken()
    {
        // Intentionally empty: there is nothing to invalidate. The configured token is the
        // only credential this provider will ever have.
    }
}
