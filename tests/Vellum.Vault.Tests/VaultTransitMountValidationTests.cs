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
