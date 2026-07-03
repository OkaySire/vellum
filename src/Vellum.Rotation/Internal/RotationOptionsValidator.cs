using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;

namespace Vellum.Rotation.Internal;

/// <summary>
/// Validates <see cref="RotationOptions"/> at application start-up so that a misconfigured
/// rotation worker fails fast at the host's <c>ValidateOnStart()</c> boundary instead of
/// silently never rotating (or spinning in a hot loop on a zero interval).
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by the DI container via TryAddEnumerable<IValidateOptions<RotationOptions>, RotationOptionsValidator>() in RotationServiceCollectionExtensions.")]
internal sealed class RotationOptionsValidator : IValidateOptions<RotationOptions>
{
    public ValidateOptionsResult Validate(string? name, RotationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> failures = [];

        if (options.RotationInterval <= TimeSpan.Zero)
        {
            failures.Add($"{nameof(RotationOptions.RotationInterval)} must be a positive duration; got {options.RotationInterval}.");
        }

        if (options.MaxDekAge <= TimeSpan.Zero)
        {
            failures.Add($"{nameof(RotationOptions.MaxDekAge)} must be a positive duration; got {options.MaxDekAge}.");
        }

        if (options.MaxRetriesPerScope < 0)
        {
            failures.Add($"{nameof(RotationOptions.MaxRetriesPerScope)} must be zero or greater; got {options.MaxRetriesPerScope}.");
        }

        if (options.RetryBaseDelay <= TimeSpan.Zero)
        {
            failures.Add($"{nameof(RotationOptions.RetryBaseDelay)} must be a positive duration; got {options.RetryBaseDelay}.");
        }

        if (options.StartupDelay < TimeSpan.Zero)
        {
            failures.Add($"{nameof(RotationOptions.StartupDelay)} must be zero or a positive duration; got {options.StartupDelay}.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
