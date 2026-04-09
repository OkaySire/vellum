using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;

namespace Vellum.Static.Internal;

/// <summary>
/// Validates <see cref="StaticOptions"/> at application start-up so that misconfiguration
/// fails fast before the first wrap/unwrap call.
/// </summary>
/// <remarks>
/// <b>Never</b> include <see cref="StaticOptions.Base64Key"/> — or any derivative of it — in
/// failure messages. Even though the provider is development-only, the same discipline that
/// keeps secrets out of logs in production must apply here.
/// </remarks>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by the DI container via TryAddEnumerable<IValidateOptions<StaticOptions>, StaticOptionsValidator>() in StaticServiceCollectionExtensions.")]
internal sealed class StaticOptionsValidator : IValidateOptions<StaticOptions>
{
    internal const int RequiredKeyLengthBytes = 32;

    public ValidateOptionsResult Validate(string? name, StaticOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> failures = [];

        if (string.IsNullOrWhiteSpace(options.Base64Key))
        {
            failures.Add(
                $"{nameof(StaticOptions.Base64Key)} must be a non-empty base64-encoded 32-byte AES-256 key.");
            return ValidateOptionsResult.Fail(failures);
        }

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(options.Base64Key);
        }
        catch (FormatException)
        {
            // Deliberately do not include the offending value in the message.
            failures.Add(
                $"{nameof(StaticOptions.Base64Key)} is not valid base64.");
            return ValidateOptionsResult.Fail(failures);
        }

        if (decoded.Length != RequiredKeyLengthBytes)
        {
            failures.Add(
                $"{nameof(StaticOptions.Base64Key)} must decode to exactly {RequiredKeyLengthBytes} bytes (AES-256); got {decoded.Length} bytes.");
            Array.Clear(decoded);
            return ValidateOptionsResult.Fail(failures);
        }

        // We validated by decoding; zero the working copy — the provider will decode again at wrap/unwrap time.
        Array.Clear(decoded);
        return ValidateOptionsResult.Success;
    }
}
