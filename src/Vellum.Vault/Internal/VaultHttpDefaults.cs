namespace Vellum.Vault.Internal;

/// <summary>
/// Constants shared by the Vault HTTP client registrations and handlers.
/// </summary>
internal static class VaultHttpDefaults
{
    /// <summary>The Vault auth header set per request by <see cref="VaultAuthenticationHandler"/>.</summary>
    internal const string TokenHeaderName = "X-Vault-Token";

    /// <summary>
    /// The name of the dedicated <see cref="HttpClient"/> used for AppRole logins. This client
    /// deliberately does NOT carry the <see cref="VaultAuthenticationHandler"/> — a login must
    /// not require a token, and routing it through the auth handler would recurse.
    /// </summary>
    internal const string AppRoleLoginClientName = "Vellum.Vault.AppRoleLogin";

    /// <summary>
    /// M-E: hard cap on the number of bytes the <see cref="HttpClient"/> will buffer from any
    /// Vault response. Legitimate Transit wrap/unwrap and AppRole login responses are small
    /// JSON documents (well under 4 KB), so 64 KB is generous. A malicious or compromised
    /// Vault returning a multi-gigabyte body causes an <see cref="HttpRequestException"/>
    /// instead of an unbounded allocation — fail closed.
    /// </summary>
    internal const long MaxResponseContentBufferBytes = 64 * 1024;
}
