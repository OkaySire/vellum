using Microsoft.Extensions.Options;

namespace Vellum.Vault.Internal;

/// <summary>
/// Validates <see cref="VaultOptions"/> at application start-up so that misconfiguration fails
/// fast at the host's <c>ValidateOnStart()</c> boundary rather than surfacing as an obscure
/// runtime error on the first wrap/unwrap call.
/// </summary>
internal sealed class VaultOptionsValidator : IValidateOptions<VaultOptions>
{
    public ValidateOptionsResult Validate(string? name, VaultOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> failures = [];

        if (string.IsNullOrWhiteSpace(options.Address))
        {
            failures.Add($"{nameof(VaultOptions.Address)} must be a non-empty absolute URI (e.g. 'https://vault.example.com:8200').");
        }
        else if (!Uri.TryCreate(options.Address, UriKind.Absolute, out Uri? parsed) ||
                 (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps))
        {
            // L-2: scrub any `user:pass@` userinfo before echoing the malformed Address in
            // the failure message. If the URI is parseable enough to have a host, prefer the
            // host form so we never leak credentials. If it is not parseable at all, cut off
            // anything before the first `@` as a best-effort defence.
            string safeEcho = ScrubUserInfo(options.Address);
            failures.Add($"{nameof(VaultOptions.Address)} ('{safeEcho}') must be an absolute http:// or https:// URI.");
        }
        else if (parsed.Scheme == Uri.UriSchemeHttp && !options.AllowInsecureHttp)
        {
            // H-A: plain http:// transmits the X-Vault-Token header and the base64-encoded
            // plaintext DEKs (encrypt request body / decrypt response body) in cleartext.
            // Fail closed unless the consumer explicitly opts in for local development.
            string safeEcho = ScrubUserInfo(options.Address);
            failures.Add(
                $"{nameof(VaultOptions.Address)} ('{safeEcho}') uses plain http://, which would transmit " +
                $"the Vault token and plaintext DEKs in cleartext. Use https://, or set " +
                $"{nameof(VaultOptions.AllowInsecureHttp)} = true for local development only " +
                "(e.g. against 'vault server -dev').");
        }

        // Auth matrix: each method requires exactly its own credentials and forbids the other
        // method's fields, so a half-migrated configuration fails fast instead of silently
        // using the wrong credential. Credential VALUES are never echoed in failure messages.
        switch (options.AuthMethod)
        {
            case VaultAuthMethod.Token:
                if (string.IsNullOrWhiteSpace(options.Token))
                {
                    // Never include the token value itself in the failure message.
                    failures.Add($"{nameof(VaultOptions.Token)} must be a non-empty Vault auth token when " +
                                 $"{nameof(VaultOptions.AuthMethod)} is {nameof(VaultAuthMethod.Token)}.");
                }

                if (!string.IsNullOrWhiteSpace(options.RoleId) || !string.IsNullOrWhiteSpace(options.SecretId))
                {
                    failures.Add($"{nameof(VaultOptions.RoleId)} and {nameof(VaultOptions.SecretId)} must be empty when " +
                                 $"{nameof(VaultOptions.AuthMethod)} is {nameof(VaultAuthMethod.Token)}; set " +
                                 $"{nameof(VaultOptions.AuthMethod)} = {nameof(VaultAuthMethod.AppRole)} to use AppRole credentials.");
                }

                break;

            case VaultAuthMethod.AppRole:
                if (string.IsNullOrWhiteSpace(options.RoleId))
                {
                    failures.Add($"{nameof(VaultOptions.RoleId)} must be non-empty when " +
                                 $"{nameof(VaultOptions.AuthMethod)} is {nameof(VaultAuthMethod.AppRole)}.");
                }

                if (string.IsNullOrWhiteSpace(options.SecretId))
                {
                    failures.Add($"{nameof(VaultOptions.SecretId)} must be non-empty when " +
                                 $"{nameof(VaultOptions.AuthMethod)} is {nameof(VaultAuthMethod.AppRole)}.");
                }

                if (!string.IsNullOrWhiteSpace(options.Token))
                {
                    failures.Add($"{nameof(VaultOptions.Token)} must be empty when " +
                                 $"{nameof(VaultOptions.AuthMethod)} is {nameof(VaultAuthMethod.AppRole)}; the token is " +
                                 "acquired via AppRole login.");
                }

                string[] appRoleMountSegments = (options.AppRoleMount ?? string.Empty)
                    .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

                if (appRoleMountSegments.Length == 0)
                {
                    failures.Add($"{nameof(VaultOptions.AppRoleMount)} must be a non-empty AppRole mount path " +
                                 "(e.g. 'approle').");
                }
                else if (VaultMountPath.HasRelativeSegment(appRoleMountSegments))
                {
                    // Same defect as TransitMount below, and worse in consequence: the login POST
                    // carries RoleId and SecretId, so a normalised-away dot segment would send the
                    // credentials to a path other than the configured auth mount. The offending
                    // value is never echoed.
                    failures.Add($"{nameof(VaultOptions.AppRoleMount)} must not contain a '.' or '..' path segment: " +
                                 "an AppRole mount is an auth-method name (e.g. 'approle' or a nested " +
                                 "'team-a/approle'), not a relative path. A dot segment would be normalised away by " +
                                 "the URI layer and post the AppRole credentials to a different Vault path than the " +
                                 "one configured.");
                }

                break;

            default:
                failures.Add($"{nameof(VaultOptions.AuthMethod)} value '{options.AuthMethod}' is not a recognised " +
                             $"{nameof(VaultAuthMethod)}.");
                break;
        }

        if (options.TokenRenewalThreshold <= 0 || options.TokenRenewalThreshold > 1)
        {
            failures.Add($"{nameof(VaultOptions.TokenRenewalThreshold)} must be in (0, 1]; got " +
                         $"{options.TokenRenewalThreshold.ToString(System.Globalization.CultureInfo.InvariantCulture)}.");
        }

        if (string.IsNullOrWhiteSpace(options.KeyName))
        {
            failures.Add($"{nameof(VaultOptions.KeyName)} must be a non-empty Vault Transit key name.");
        }

        // A mount that is empty once normalised renders 'v1//encrypt/key', and Vault answers that
        // with a 404 that names no cause. Raise it here, where the message can name the property.
        // Surrounding slashes are NOT a failure: 'transit/' is normalised, not rejected — an
        // operator writing it has made no design mistake.
        string[] transitMountSegments = (options.TransitMount ?? string.Empty)
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (transitMountSegments.Length == 0)
        {
            failures.Add($"{nameof(VaultOptions.TransitMount)} must be a non-empty Transit secrets-engine mount " +
                         "path (e.g. 'transit', 'transit-zone-b', or a nested 'zone-b/transit'); leading and " +
                         "trailing slashes are optional and are normalised away.");
        }
        else if (VaultMountPath.HasRelativeSegment(transitMountSegments))
        {
            // A '.' or '..' segment is not merely useless: it holds no character that
            // Uri.EscapeDataString escapes, so it survives the per-segment escaping in
            // VaultKeyEncryptionProvider.BuildMountPath and Uri then normalises the path —
            // measured, 'transit/../auth/token' issued a request to '/v1/auth/token/encrypt/{key}'.
            // The offending value is never echoed (same rule as the Address failures above).
            failures.Add($"{nameof(VaultOptions.TransitMount)} must not contain a '.' or '..' path segment: a " +
                         "Transit mount is a secrets-engine name (e.g. 'transit', 'transit-zone-b', or a nested " +
                         "'zone-b/transit'), not a relative path. A dot segment would be normalised away by the " +
                         "URI layer and send wrap/unwrap calls to a different Vault endpoint than the one " +
                         "configured.");
        }

        if (options.HttpTimeout <= TimeSpan.Zero)
        {
            failures.Add($"{nameof(VaultOptions.HttpTimeout)} must be a positive duration; got {options.HttpTimeout}.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    /// <summary>
    /// Removes any <c>user:pass@</c> userinfo prefix from the host portion of the given
    /// address so that an accidentally-configured credential never reaches a log.
    /// </summary>
    private static string ScrubUserInfo(string address)
    {
        // If Uri.TryCreate fails to parse even the host at all, fall back to string surgery:
        // cut off everything up to and including the first `@` in the scheme-less portion.
        int schemeDelimiter = address.IndexOf("://", StringComparison.Ordinal);
        if (schemeDelimiter < 0)
        {
            int at = address.IndexOf('@', StringComparison.Ordinal);
            return at < 0 ? address : address[(at + 1)..];
        }

        string scheme = address[..schemeDelimiter];
        string remainder = address[(schemeDelimiter + 3)..];
        int atInRemainder = remainder.IndexOf('@', StringComparison.Ordinal);
        if (atInRemainder < 0)
        {
            return address;
        }

        return $"{scheme}://{remainder[(atInRemainder + 1)..]}";
    }
}
