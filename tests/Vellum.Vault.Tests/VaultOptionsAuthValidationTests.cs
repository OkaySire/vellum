using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Vellum.Vault.Tests;

/// <summary>
/// Validation matrix for the G1 auth options: each <see cref="VaultAuthMethod"/> requires
/// exactly its own credentials and forbids the other method's fields.
/// </summary>
public sealed class VaultOptionsAuthValidationTests
{
    private static OptionsValidationException ValidationFailureFor(Action<VaultOptions> configure)
    {
        Action act = ActFor(configure);
        return act.Should().Throw<OptionsValidationException>().Which;
    }

    private static Action ActFor(Action<VaultOptions> configure)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddVaultProvider(configure);
        ServiceProvider sp = services.BuildServiceProvider();
        IOptions<VaultOptions> options = sp.GetRequiredService<IOptions<VaultOptions>>();
        return () => _ = options.Value;
    }

    private static void ConfigureValidAppRole(VaultOptions opts)
    {
        opts.Address = "https://vault.example:8200";
        opts.KeyName = "my-kek";
        opts.AuthMethod = VaultAuthMethod.AppRole;
        opts.RoleId = "role-123";
        opts.SecretId = "secret-456";
    }

    [Fact]
    public void AppRole_Valid_PassesValidation()
    {
        Action act = ActFor(ConfigureValidAppRole);

        act.Should().NotThrow();
    }

    [Fact]
    public void AppRole_MissingRoleId_FailsValidation()
    {
        OptionsValidationException ex = ValidationFailureFor(opts =>
        {
            ConfigureValidAppRole(opts);
            opts.RoleId = "";
        });

        ex.Failures.Should().Contain(f => f.Contains("RoleId", StringComparison.Ordinal));
    }

    [Fact]
    public void AppRole_MissingSecretId_FailsValidation()
    {
        OptionsValidationException ex = ValidationFailureFor(opts =>
        {
            ConfigureValidAppRole(opts);
            opts.SecretId = "";
        });

        ex.Failures.Should().Contain(f => f.Contains("SecretId", StringComparison.Ordinal));
    }

    [Fact]
    public void AppRole_WithTokenSet_FailsValidation_MixedCredentials()
    {
        OptionsValidationException ex = ValidationFailureFor(opts =>
        {
            ConfigureValidAppRole(opts);
            opts.Token = "hvs.leftover";
        });

        ex.Failures.Should().Contain(f => f.Contains("Token", StringComparison.Ordinal)
                                          && f.Contains("AppRole", StringComparison.Ordinal));
    }

    [Fact]
    public void TokenMethod_WithAppRoleFieldsSet_FailsValidation_MixedCredentials()
    {
        OptionsValidationException ex = ValidationFailureFor(opts =>
        {
            opts.Address = "https://vault.example:8200";
            opts.KeyName = "my-kek";
            opts.Token = "hvs.abc";
            opts.RoleId = "role-123";
            opts.SecretId = "secret-456";
        });

        ex.Failures.Should().Contain(f => f.Contains("RoleId", StringComparison.Ordinal));
    }

    [Fact]
    public void AppRole_EmptyMount_FailsValidation()
    {
        OptionsValidationException ex = ValidationFailureFor(opts =>
        {
            ConfigureValidAppRole(opts);
            opts.AppRoleMount = " ";
        });

        ex.Failures.Should().Contain(f => f.Contains("AppRoleMount", StringComparison.Ordinal));
    }

    /// <summary>
    /// A <c>.</c> or <c>..</c> segment in the AppRole mount is rejected at start-up: it survives
    /// the per-segment escaping in <c>AppRoleVaultTokenProvider.BuildLoginPath</c> and the URI layer
    /// then normalises it away. Measured on the pre-fix code, <c>approle/../../v1/sys/health</c>
    /// posted the login — <see cref="VaultOptions.RoleId"/> and
    /// <see cref="VaultOptions.SecretId"/> included — to
    /// <c>http://vault.test:8200/v1/v1/sys/health/login</c>.
    /// </summary>
    [Theory]
    [InlineData("approle/../../v1/sys/health")]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("approle/..")]
    [InlineData(" .. ")]
    public void AppRole_DotOrDotDotSegmentInMount_FailsValidation(string mount)
    {
        OptionsValidationException ex = ValidationFailureFor(opts =>
        {
            ConfigureValidAppRole(opts);
            opts.AppRoleMount = mount;
        });

        ex.Failures.Should().Contain(f => f.Contains("AppRoleMount", StringComparison.Ordinal));
        ex.Failures.Should().NotContain(f => f.Contains("sys/health", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0.0)]
    [InlineData(-0.5)]
    [InlineData(1.01)]
    [InlineData(2.0)]
    public void TokenRenewalThreshold_OutOfRange_FailsValidation(double threshold)
    {
        OptionsValidationException ex = ValidationFailureFor(opts =>
        {
            ConfigureValidAppRole(opts);
            opts.TokenRenewalThreshold = threshold;
        });

        ex.Failures.Should().Contain(f => f.Contains("TokenRenewalThreshold", StringComparison.Ordinal));
    }

    [Fact]
    public void TokenRenewalThreshold_ExactlyOne_PassesValidation()
    {
        Action act = ActFor(opts =>
        {
            ConfigureValidAppRole(opts);
            opts.TokenRenewalThreshold = 1.0;
        });

        act.Should().NotThrow();
    }

    [Fact]
    public void ValidationFailures_NeverEchoCredentialValues()
    {
        OptionsValidationException ex = ValidationFailureFor(opts =>
        {
            ConfigureValidAppRole(opts);
            opts.Token = "hvs.leftover-secret";
        });

        foreach (string failure in ex.Failures)
        {
            failure.Should().NotContain("hvs.leftover-secret", "the token value must never be echoed");
            failure.Should().NotContain("role-123", "the role id value must never be echoed");
            failure.Should().NotContain("secret-456", "the secret id value must never be echoed");
        }
    }

    [Fact]
    public void Defaults_AreTokenMethod_Threshold08_MountApprole_ResilienceOn()
    {
        VaultOptions options = new();

        options.AuthMethod.Should().Be(VaultAuthMethod.Token);
        options.TokenRenewalThreshold.Should().Be(0.8);
        options.AppRoleMount.Should().Be("approle");
        options.EnableResilience.Should().BeTrue();
    }
}
