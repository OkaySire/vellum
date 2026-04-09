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
            failures.Add($"{nameof(VaultOptions.Address)} ('{options.Address}') must be an absolute http:// or https:// URI.");
        }

        if (string.IsNullOrWhiteSpace(options.Token))
        {
            // Never include the token value itself in the failure message.
            failures.Add($"{nameof(VaultOptions.Token)} must be a non-empty Vault auth token.");
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
}
