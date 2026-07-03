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

                if (string.IsNullOrWhiteSpace(options.AppRoleMount))
                {
                    failures.Add($"{nameof(VaultOptions.AppRoleMount)} must be a non-empty AppRole mount path " +
                                 "(e.g. 'approle').");
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
