using FluentAssertions;
using Microsoft.Extensions.Options;
using Vellum.Rotation.Internal;
using Xunit;

namespace Vellum.Rotation.Tests;

public sealed class RotationOptionsValidatorTests
{
    private readonly RotationOptionsValidator _validator = new();

    [Fact]
    public void Validate_Defaults_Succeeds()
    {
        RotationOptions options = new();

        ValidateOptionsResult result = _validator.Validate(null, options);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_ZeroStartupDelay_Succeeds()
    {
        RotationOptions options = new() { StartupDelay = TimeSpan.Zero };

        ValidateOptionsResult result = _validator.Validate(null, options);

        result.Succeeded.Should().BeTrue("a zero startup delay (start immediately) is a legitimate configuration");
    }

    [Fact]
    public void Validate_ZeroMaxRetriesPerScope_Succeeds()
    {
        RotationOptions options = new() { MaxRetriesPerScope = 0 };

        ValidateOptionsResult result = _validator.Validate(null, options);

        result.Succeeded.Should().BeTrue("zero retries (one attempt per scope per tick) is a legitimate configuration");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_NonPositiveRotationInterval_Fails(int hours)
    {
        RotationOptions options = new() { RotationInterval = TimeSpan.FromHours(hours) };

        ValidateOptionsResult result = _validator.Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(nameof(RotationOptions.RotationInterval));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_NonPositiveMaxDekAge_Fails(int hours)
    {
        RotationOptions options = new() { MaxDekAge = TimeSpan.FromHours(hours) };

        ValidateOptionsResult result = _validator.Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(nameof(RotationOptions.MaxDekAge));
    }

    [Fact]
    public void Validate_NegativeMaxRetriesPerScope_Fails()
    {
        RotationOptions options = new() { MaxRetriesPerScope = -1 };

        ValidateOptionsResult result = _validator.Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(nameof(RotationOptions.MaxRetriesPerScope));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void Validate_NonPositiveRetryBaseDelay_Fails(int seconds)
    {
        RotationOptions options = new() { RetryBaseDelay = TimeSpan.FromSeconds(seconds) };

        ValidateOptionsResult result = _validator.Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(nameof(RotationOptions.RetryBaseDelay));
    }

    [Fact]
    public void Validate_NegativeStartupDelay_Fails()
    {
        RotationOptions options = new() { StartupDelay = TimeSpan.FromSeconds(-1) };

        ValidateOptionsResult result = _validator.Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(nameof(RotationOptions.StartupDelay));
    }

    [Fact]
    public void Validate_MultipleInvalidFields_ReportsAllFailures()
    {
        RotationOptions options = new()
        {
            RotationInterval = TimeSpan.Zero,
            MaxDekAge = TimeSpan.Zero,
            MaxRetriesPerScope = -1,
        };

        ValidateOptionsResult result = _validator.Validate(null, options);

        result.Failed.Should().BeTrue();
        result.Failures.Should().HaveCount(3);
    }

    [Fact]
    public void Validate_NullOptions_Throws()
    {
        Action act = () => _validator.Validate(null, null!);

        act.Should().Throw<ArgumentNullException>();
    }
}
