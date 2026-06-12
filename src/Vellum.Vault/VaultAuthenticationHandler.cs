using System.Net;
using Vellum.Vault.Internal;

namespace Vellum.Vault;

/// <summary>
/// A <see cref="DelegatingHandler"/> that stamps the <c>X-Vault-Token</c> header on every
/// outgoing Vault request, fetching the token per request from <see cref="IVaultTokenProvider"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>403 handling.</b> A <c>403 Forbidden</c> from Vault usually means the token expired or
/// was revoked — not that the policy denies the operation. On a 403 this handler calls
/// <see cref="IVaultTokenProvider.InvalidateToken"/>, fetches a fresh token, and retries the
/// request <b>once</b>. This covers token expiry, not authorization failures: a second 403
/// propagates to the caller. When the fresh token is identical to the one that just failed
/// (static-token deployments — see <see cref="StaticVaultTokenProvider"/>), the retry is
/// skipped entirely and the original 403 is returned.
/// </para>
/// <para>
/// <b>Pipeline position.</b> <c>AddVaultProvider</c> registers this handler <b>inside</b> the
/// standard resilience handler, so every resilience retry attempt re-enters this handler and
/// gets a fresh-token opportunity.
/// </para>
/// <para>
/// Re-sending the same <see cref="HttpRequestMessage"/> from inside a handler is safe: the
/// "already sent" guard lives in <see cref="HttpClient"/>, not in the handler chain, and the
/// <c>JsonContent</c> bodies used by Vellum serialize on demand and can be written more than
/// once (the same mechanism the resilience handler relies on).
/// </para>
/// </remarks>
public sealed class VaultAuthenticationHandler(IVaultTokenProvider tokenProvider) : DelegatingHandler
{
    private readonly IVaultTokenProvider _tokenProvider =
        tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        string token = await _tokenProvider.GetTokenAsync(cancellationToken).ConfigureAwait(false);
        SetTokenHeader(request, token);

        HttpResponseMessage response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Forbidden)
        {
            return response;
        }

        // The cached token may have expired or been revoked. Force re-acquisition and retry
        // exactly once with the fresh token.
        _tokenProvider.InvalidateToken();
        string freshToken = await _tokenProvider.GetTokenAsync(cancellationToken).ConfigureAwait(false);
        if (string.Equals(freshToken, token, StringComparison.Ordinal))
        {
            // The provider cannot mint a new token (static token): retrying with the
            // identical credential would only duplicate the failing request. Fail closed
            // with the original 403.
            return response;
        }

        response.Dispose();
        SetTokenHeader(request, freshToken);
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private static void SetTokenHeader(HttpRequestMessage request, string token)
    {
        request.Headers.Remove(VaultHttpDefaults.TokenHeaderName);
        request.Headers.TryAddWithoutValidation(VaultHttpDefaults.TokenHeaderName, token);
    }
}
