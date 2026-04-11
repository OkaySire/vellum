using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;

namespace Vellum.EntityFrameworkCore.Internal;

/// <summary>
/// M-7: validates <see cref="VellumEntityFrameworkOptions"/> at application start-up so that
/// common misconfigurations (empty table name, non-positive scope length, empty filter) fail
/// fast at host startup rather than later, in <c>DbContext.OnModelCreating</c> or on the first
/// <c>SaveChangesAsync</c>. Brings the EF Core extension in line with the Static and Vault
/// extensions, which already validate on start.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by the DI container via TryAddEnumerable<IValidateOptions<VellumEntityFrameworkOptions>, VellumEntityFrameworkOptionsValidator>() in VellumEntityFrameworkServiceCollectionExtensions.")]
internal sealed class VellumEntityFrameworkOptionsValidator : IValidateOptions<VellumEntityFrameworkOptions>
{
    public ValidateOptionsResult Validate(string? name, VellumEntityFrameworkOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> failures = [];

        if (string.IsNullOrWhiteSpace(options.TableName))
        {
            failures.Add(
                $"{nameof(VellumEntityFrameworkOptions.TableName)} must be a non-empty identifier.");
        }

        if (options.ScopeMaxLength <= 0)
        {
            failures.Add(
                $"{nameof(VellumEntityFrameworkOptions.ScopeMaxLength)} must be strictly positive; got {options.ScopeMaxLength}.");
        }

        if (options.WrappedProviderVersionMaxLength <= 0)
        {
            failures.Add(
                $"{nameof(VellumEntityFrameworkOptions.WrappedProviderVersionMaxLength)} must be strictly positive; got {options.WrappedProviderVersionMaxLength}.");
        }

        if (string.IsNullOrWhiteSpace(options.UniqueActiveIndexFilter))
        {
            failures.Add(
                $"{nameof(VellumEntityFrameworkOptions.UniqueActiveIndexFilter)} must be a non-empty SQL fragment. See the XML remarks on VellumEntityFrameworkOptions for per-provider syntax.");
        }

        // Column name overrides (issue #8). Empty/whitespace values would produce silent
        // migration corruption, so we treat them as fatal misconfiguration.
        ValidateColumnName(
            failures,
            nameof(VellumEntityFrameworkOptions.KeyIdColumnName),
            options.KeyIdColumnName);
        ValidateColumnName(
            failures,
            nameof(VellumEntityFrameworkOptions.ScopeColumnName),
            options.ScopeColumnName);
        ValidateColumnName(
            failures,
            nameof(VellumEntityFrameworkOptions.WrappedCiphertextColumnName),
            options.WrappedCiphertextColumnName);
        ValidateColumnName(
            failures,
            nameof(VellumEntityFrameworkOptions.WrappedProviderVersionColumnName),
            options.WrappedProviderVersionColumnName);
        ValidateColumnName(
            failures,
            nameof(VellumEntityFrameworkOptions.CreatedAtColumnName),
            options.CreatedAtColumnName);
        ValidateColumnName(
            failures,
            nameof(VellumEntityFrameworkOptions.ExpiresAtColumnName),
            options.ExpiresAtColumnName);
        ValidateColumnName(
            failures,
            nameof(VellumEntityFrameworkOptions.IsActiveColumnName),
            options.IsActiveColumnName);

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    private static void ValidateColumnName(List<string> failures, string propertyName, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            failures.Add($"{propertyName} must be a non-empty identifier.");
        }
    }
}
