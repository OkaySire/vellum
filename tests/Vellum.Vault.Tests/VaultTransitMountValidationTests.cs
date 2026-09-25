using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Vellum.Vault.Tests;

/// <summary>
/// Validation of <see cref="VaultOptions.TransitMount"/>. A mount that is empty once normalised
/// would render <c>v1//encrypt/key</c>, which Vault answers with a <c>404</c> that names no cause:
/// the failure therefore has to be raised by the validator, where the message can name the
/// offending property.
/// </summary>
public sealed class VaultTransitMountValidationTests
{
    private static Action ActFor(Action<VaultOptions> configure)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(configure);
        ServiceProvider sp = services.BuildServiceProvider();
        IOptions<VaultOptions> options = sp.GetRequiredService<IOptions<VaultOptions>>();
        return () => _ = options.Value;
    }

    private static void ConfigureValid(VaultOptions opts)
    {
        opts.Address = "https://vault.example:8200";
        opts.KeyName = "my-kek";
        opts.Token = "hvs.test-token";
    }

    [Fact]
    public void DefaultMount_PassesValidation()
    {
        Action act = ActFor(ConfigureValid);

        act.Should().NotThrow();
    }

    [Theory]
    [InlineData("transit-zone-b")]
    [InlineData("zone-b/transit")]
    [InlineData("/transit-zone-b/")]
    public void NonEmptyMount_PassesValidation(string mount)
    {
        Action act = ActFor(opts =>
        {
            ConfigureValid(opts);
            opts.TransitMount = mount;
        });

        act.Should().NotThrow();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("/")]
    [InlineData("//")]
    [InlineData(" / ")]
    public void EmptyOrSlashOnlyMount_FailsValidation(string mount)
    {
        Action act = ActFor(opts =>
        {
            ConfigureValid(opts);
            opts.TransitMount = mount;
        });

        OptionsValidationException ex = act.Should().Throw<OptionsValidationException>().Which;
        ex.Failures.Should().Contain(f => f.Contains("TransitMount", StringComparison.Ordinal));
    }

    /// <summary>
    /// A <c>.</c> or <c>..</c> segment is rejected at start-up. It is not a harmless no-op: neither
    /// dot segment contains a character that <c>Uri.EscapeDataString</c> escapes, so it survives
    /// the per-segment escaping in <c>VaultKeyEncryptionProvider.BuildMountPath</c> and the URI
    /// layer then normalises the path. Measured on the pre-fix code, <c>transit/../auth/token</c>
    /// sent the wrap request to <c>http://vault.test:8200/v1/auth/token/encrypt/test-key</c>
    /// instead of <c>.../v1/transit/encrypt/test-key</c>.
    /// </summary>
    [Theory]
    [InlineData("transit/../auth/token")]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("transit/..")]
    [InlineData("transit/./x")]
    [InlineData("/../transit/")]
    [InlineData(" .. ")]
    public void DotOrDotDotSegment_FailsValidation(string mount)
    {
        Action act = ActFor(opts =>
        {
            ConfigureValid(opts);
            opts.TransitMount = mount;
        });

        OptionsValidationException ex = act.Should().Throw<OptionsValidationException>().Which;
        ex.Failures.Should().Contain(f => f.Contains("TransitMount", StringComparison.Ordinal));
    }

    /// <summary>
    /// The failure names the property but never carries the rejected value — the same rule the
    /// validator applies to <see cref="VaultOptions.Address"/> via its <c>ScrubUserInfo</c> path.
    /// </summary>
    [Fact]
    public void DotDotSegment_FailureMessageDoesNotCarryTheValue()
    {
        Action act = ActFor(opts =>
        {
            ConfigureValid(opts);
            opts.TransitMount = "transit/../auth/token";
        });

        OptionsValidationException ex = act.Should().Throw<OptionsValidationException>().Which;
        ex.Failures.Should().NotContain(f => f.Contains("auth/token", StringComparison.Ordinal));
    }

    /// <summary>
    /// The witness for the rejection above: a mount whose segments merely CONTAIN dots, without
    /// being <c>.</c> or <c>..</c>, is still legitimate and must keep passing — otherwise the new
    /// rule would be a blanket ban on the character rather than on the relative segment.
    /// </summary>
    [Theory]
    [InlineData("transit.v2")]
    [InlineData("..transit")]
    [InlineData("transit..")]
    [InlineData("zone-b/transit.v2")]
    [InlineData("...")]
    public void MountWithDotsInsideASegment_StillPassesValidation(string mount)
    {
        Action act = ActFor(opts =>
        {
            ConfigureValid(opts);
            opts.TransitMount = mount;
        });

        act.Should().NotThrow();
    }

    /// <summary>
    /// The failure message must not blame <see cref="VaultOptions.AppRoleMount"/>: the two mounts
    /// are independent, and confusing them would send an operator to the auth configuration.
    /// </summary>
    [Fact]
    public void EmptyMount_FailureMessageDoesNotMentionAppRoleMount()
    {
        Action act = ActFor(opts =>
        {
            ConfigureValid(opts);
            opts.TransitMount = "";
        });

        OptionsValidationException ex = act.Should().Throw<OptionsValidationException>().Which;
        ex.Failures.Should().NotContain(f => f.Contains("AppRoleMount", StringComparison.Ordinal));
    }
}
