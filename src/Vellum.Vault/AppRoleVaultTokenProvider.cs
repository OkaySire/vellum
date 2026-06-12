using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Vellum.Vault.Internal;

namespace Vellum.Vault;

/// <summary>
/// An <see cref="IVaultTokenProvider"/> that logs in via the Vault AppRole auth method
/// (<c>POST /v1/auth/{mount}/login</c>) and caches the issued client token until it nears
/// expiry.
/// </summary>
/// <remarks>
/// <para>
/// <b>Re-login, not renew-self.</b> When the cached token passes
/// <c>lease_duration × <see cref="VaultOptions.TokenRenewalThreshold"/></c> of its lifetime,
/// this provider performs a fresh AppRole login instead of calling
/// <c>POST /v1/auth/token/renew-self</c>. A re-login is stateless (no tracking of renew
/// counters, <c>max_ttl</c> ceilings, or the <c>renewable</c> flag — which is why the
/// <c>renewable</c> field of the login response is ignored), always succeeds while the
/// role credentials are valid, and an AppRole login is a cheap single round-trip. The
/// trade-off — slightly more tokens minted on the Vault side — is negligible for a provider
/// that logs in at most once per threshold window.
/// </para>
/// <para>
/// <b>Thread safety.</b> The token cache is guarded by a <see cref="SemaphoreSlim"/> with a
/// double-check, so concurrent callers that miss the cache share a single login round-trip.
/// The cache-hit fast path is lock-free.
/// </para>
/// <para>
/// <b>Lease handling.</b> A <c>lease_duration</c> of <c>0</c> means the token never expires
/// (Vault semantics); the token is then cached until <see cref="InvalidateToken"/> is called.
/// </para>
/// <para>
/// <b>Secrets.</b> The role id, secret id, and issued tokens are never logged and never
/// embedded in exception messages.
/// </para>
/// <para>
/// <b>HTTP.</b> Logins go through a dedicated named <see cref="HttpClient"/>
/// (registered by <c>AddVaultProvider</c>) that does <b>not</b> carry the
/// <see cref="VaultAuthenticationHandler"/> — a login must not require a token, and routing
/// it through the auth handler would recurse.
/// </para>
/// </remarks>
public sealed partial class AppRoleVaultTokenProvider(
    IHttpClientFactory httpClientFactory,
    IOptions<VaultOptions> options,
    TimeProvider timeProvider,
    ILogger<AppRoleVaultTokenProvider> logger) : IVaultTokenProvider, IDisposable
{
    private readonly IHttpClientFactory _httpClientFactory =
        httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
    private readonly VaultOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ILogger<AppRoleVaultTokenProvider> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    private readonly SemaphoreSlim _loginLock = new(1, 1);
    private CachedVaultToken? _cached;

    /// <inheritdoc />
    public ValueTask<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        // Lock-free fast path: a cached token that has not yet reached its refresh point is
        // returned synchronously without touching the semaphore.
        CachedVaultToken? cached = Volatile.Read(ref _cached);
        if (cached is not null && _timeProvider.GetUtcNow() < cached.RefreshAt)
        {
            return new ValueTask<string>(cached.Token);
        }

        return new ValueTask<string>(LoginCoreAsync(cancellationToken));
    }

    /// <inheritdoc />
    public void InvalidateToken()
    {
        Volatile.Write(ref _cached, null);
        LogTokenInvalidated(_logger);
    }

    /// <summary>Releases the internal login lock.</summary>
    public void Dispose()
    {
        _loginLock.Dispose();
        GC.SuppressFinalize(this);
    }

    private async Task<string> LoginCoreAsync(CancellationToken cancellationToken)
    {
        await _loginLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Double-check under the lock: a concurrent caller may have completed the login
            // while we were waiting — share its token instead of logging in again.
            CachedVaultToken? cached = Volatile.Read(ref _cached);
            if (cached is not null && _timeProvider.GetUtcNow() < cached.RefreshAt)
            {
                return cached.Token;
            }

            VaultAppRoleLoginRequest requestDto = new(_options.RoleId, _options.SecretId);
            using JsonContent content = JsonContent.Create(requestDto, VaultJsonContext.Default.VaultAppRoleLoginRequest);
            string relativePath = BuildLoginPath(_options.AppRoleMount);

            using HttpClient httpClient = _httpClientFactory.CreateClient(VaultHttpDefaults.AppRoleLoginClientName);
            using HttpResponseMessage response = await httpClient
                .PostAsync(new Uri(relativePath, UriKind.Relative), content, cancellationToken)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                string errorBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                string truncatedBody = VaultDiagnostics.TruncateForDiagnostics(errorBody);
                LogLoginFailed(_logger, (int)response.StatusCode, truncatedBody);
                throw new InvalidOperationException(
                    $"Vault AppRole login failed with HTTP {(int)response.StatusCode} ({response.StatusCode}): {truncatedBody}");
            }

            VaultAppRoleLoginResponse? parsed;
            try
            {
                parsed = await response.Content
                    .ReadFromJsonAsync(VaultJsonContext.Default.VaultAppRoleLoginResponse, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (JsonException ex)
            {
                LogLoginJsonParseFailed(_logger, ex.Message);
                throw;
            }

            string? clientToken = parsed?.Auth?.ClientToken;
            if (string.IsNullOrEmpty(clientToken))
            {
                throw new InvalidOperationException("Vault AppRole login returned a null or empty client token.");
            }

            long leaseDurationSeconds = parsed!.Auth!.LeaseDuration;
            DateTimeOffset refreshAt = leaseDurationSeconds > 0
                ? _timeProvider.GetUtcNow() + TimeSpan.FromSeconds(leaseDurationSeconds * _options.TokenRenewalThreshold)
                : DateTimeOffset.MaxValue; // lease_duration 0 = non-expiring token (Vault semantics)

            Volatile.Write(ref _cached, new CachedVaultToken(clientToken, refreshAt));
            LogLoginSucceeded(_logger, _options.AppRoleMount, leaseDurationSeconds);
            return clientToken;
        }
        finally
        {
            _loginLock.Release();
        }
    }

    /// <summary>
    /// Builds the relative AppRole login URL. Each path segment of the mount is URL-encoded
    /// individually so that mounts at nested paths (e.g. <c>team-a/approle</c>) keep their
    /// <c>/</c> separators while reserved characters inside a segment are transmitted safely.
    /// </summary>
    private static string BuildLoginPath(string mount)
    {
        string[] segments = mount.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        string escapedMount = string.Join('/', segments.Select(Uri.EscapeDataString));
        return $"v1/auth/{escapedMount}/login";
    }

    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Debug,
        Message = "Vault AppRole login succeeded for mount {Mount} (lease duration {LeaseDurationSeconds}s).")]
    private static partial void LogLoginSucceeded(ILogger logger, string mount, long leaseDurationSeconds);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Error,
        Message = "Vault AppRole login failed with HTTP {StatusCode}: {ErrorBody}")]
    private static partial void LogLoginFailed(ILogger logger, int statusCode, string errorBody);

    [LoggerMessage(
        EventId = 3,
        Level = LogLevel.Error,
        Message = "Vault AppRole login response JSON could not be parsed: {ErrorMessage}")]
    private static partial void LogLoginJsonParseFailed(ILogger logger, string errorMessage);

    [LoggerMessage(
        EventId = 4,
        Level = LogLevel.Debug,
        Message = "Vault token invalidated; a fresh AppRole login will run on the next request.")]
    private static partial void LogTokenInvalidated(ILogger logger);

    /// <summary>
    /// Immutable snapshot of an issued token and the instant after which it must be replaced.
    /// A single reference field keeps reads/writes atomic without extra locking on the fast path.
    /// </summary>
    private sealed record CachedVaultToken(string Token, DateTimeOffset RefreshAt);
}
