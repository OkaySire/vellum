using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Vellum.Rotation.Tests;

public sealed class RotationServiceCollectionExtensionsTests
{
    [Fact]
    public void AddVellumRotation_NullServices_Throws()
    {
        IServiceCollection services = null!;

        Action act = () => services.AddVellumRotation();

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddVellumRotation_RegistersHostedService()
    {
        ServiceCollection services = new();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddVellumRotation();
        using ServiceProvider provider = services.BuildServiceProvider();

        IEnumerable<IHostedService> hostedServices = provider.GetServices<IHostedService>();

        hostedServices.Should().ContainSingle(service => service is DekRotationBackgroundService);
    }

    [Fact]
    public void AddVellumRotation_WithoutConfigure_UsesDefaults()
    {
        ServiceCollection services = new();
        services.AddVellumRotation();
        using ServiceProvider provider = services.BuildServiceProvider();

        RotationOptions options = provider.GetRequiredService<IOptions<RotationOptions>>().Value;

        options.RotationInterval.Should().Be(TimeSpan.FromHours(24));
        options.MaxDekAge.Should().Be(TimeSpan.FromHours(24));
        options.MaxRetriesPerScope.Should().Be(3);
        options.RetryBaseDelay.Should().Be(TimeSpan.FromSeconds(5));
        options.StartupDelay.Should().Be(TimeSpan.FromMinutes(1));
    }

    [Fact]
    public void AddVellumRotation_ConfigureDelegate_IsApplied()
    {
        ServiceCollection services = new();
        services.AddVellumRotation(options =>
        {
            options.RotationInterval = TimeSpan.FromHours(6);
            options.MaxDekAge = TimeSpan.FromHours(12);
        });
        using ServiceProvider provider = services.BuildServiceProvider();

        RotationOptions options = provider.GetRequiredService<IOptions<RotationOptions>>().Value;

        options.RotationInterval.Should().Be(TimeSpan.FromHours(6));
        options.MaxDekAge.Should().Be(TimeSpan.FromHours(12));
    }

    [Fact]
    public void AddVellumRotation_RegistersTimeProvider()
    {
        ServiceCollection services = new();
        services.AddVellumRotation();
        using ServiceProvider provider = services.BuildServiceProvider();

        TimeProvider timeProvider = provider.GetRequiredService<TimeProvider>();

        timeProvider.Should().BeSameAs(TimeProvider.System);
    }

    [Fact]
    public void AddVellumRotation_ValidateOnStart_RegistersStartupValidator()
    {
        // L20: ValidateOnStart() wires up IStartupValidator (public in Microsoft.Extensions.Options)
        // — invoking it directly tests the run-on-start wiring without a Hosting dependency.
        ServiceCollection services = new();
        services.AddVellumRotation(options => options.RotationInterval = TimeSpan.Zero);
        using ServiceProvider provider = services.BuildServiceProvider();
        IStartupValidator validator = provider.GetRequiredService<IStartupValidator>();

        Action act = validator.Validate;

        act.Should().Throw<OptionsValidationException>();
    }

    [Fact]
    public void AddVellumRotation_ValidateOnStart_PassesOnValidConfiguration()
    {
        ServiceCollection services = new();
        services.AddVellumRotation(options => options.RotationInterval = TimeSpan.FromHours(12));
        using ServiceProvider provider = services.BuildServiceProvider();
        IStartupValidator validator = provider.GetRequiredService<IStartupValidator>();

        Action act = validator.Validate;

        act.Should().NotThrow();
    }
}
