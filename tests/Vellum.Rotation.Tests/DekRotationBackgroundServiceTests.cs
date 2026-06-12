using FluentAssertions;
using Vellum.Rotation.Tests.Fixtures;
using Xunit;

namespace Vellum.Rotation.Tests;

public sealed class DekRotationBackgroundServiceTests : IDisposable
{
    private readonly RotationServiceHarness _harness = new();

    public void Dispose() => _harness.Dispose();

    [Fact]
    public async Task RunTickAsync_YoungActiveKey_IsSkipped()
    {
        _harness.Store.SetActiveKey("tenant:young", DateTimeOffset.UtcNow - TimeSpan.FromMinutes(5));
        using DekRotationBackgroundService service = _harness.CreateService(
            RotationServiceHarness.FastOptions(maxDekAge: TimeSpan.FromHours(1)));

        await service.RunTickAsync(CancellationToken.None);

        _harness.DekManager.RotateAttempts.Should().BeEmpty(
            "a key younger than MaxDekAge must not trigger a rotation (no pointless KEK wrap calls)");
    }

    [Fact]
    public async Task RunTickAsync_OldActiveKey_IsRotated()
    {
        _harness.Store.SetActiveKey("tenant:old", DateTimeOffset.UtcNow - TimeSpan.FromHours(2));
        using DekRotationBackgroundService service = _harness.CreateService(
            RotationServiceHarness.FastOptions(maxDekAge: TimeSpan.FromHours(1)));

        await service.RunTickAsync(CancellationToken.None);

        _harness.DekManager.RotateAttempts.Should().Equal("tenant:old");
    }

    [Fact]
    public async Task RunTickAsync_ScopeWithoutActiveKey_IsSkippedWithoutError()
    {
        // Simulates a scope revoked (DeactivateAllAsync) between the scope listing and the
        // per-scope read: the worker must skip it, never re-create a key over a revocation.
        _harness.Store.RegisterScopeWithoutActiveKey("tenant:revoked");
        using DekRotationBackgroundService service = _harness.CreateService(
            RotationServiceHarness.FastOptions(maxDekAge: TimeSpan.FromHours(1)));

        Func<Task> act = () => service.RunTickAsync(CancellationToken.None);

        await act.Should().NotThrowAsync();
        _harness.DekManager.RotateAttempts.Should().BeEmpty();
    }

    [Fact]
    public async Task RunTickAsync_TransientFailures_RetriesWithinTick_ThenSucceeds()
    {
        _harness.Store.SetActiveKey("tenant:flaky", DateTimeOffset.UtcNow - TimeSpan.FromHours(2));
        _harness.DekManager.FailTimes("tenant:flaky", failures: 2);
        using DekRotationBackgroundService service = _harness.CreateService(
            RotationServiceHarness.FastOptions(maxDekAge: TimeSpan.FromHours(1), maxRetriesPerScope: 3));

        await service.RunTickAsync(CancellationToken.None);

        // 2 failed attempts + 1 success, all inside the same tick — a Vault blip must not
        // postpone the rotation by a full RotationInterval.
        _harness.DekManager.RotateAttempts.Should().Equal("tenant:flaky", "tenant:flaky", "tenant:flaky");
        _harness.DekManager.FirstSuccessfulRotation.IsCompleted.Should().BeTrue();
    }

    [Fact]
    public async Task RunTickAsync_PermanentFailure_GivesUpAfterMaxRetries_WithoutThrowing()
    {
        _harness.Store.SetActiveKey("tenant:down", DateTimeOffset.UtcNow - TimeSpan.FromHours(2));
        _harness.DekManager.AlwaysFail("tenant:down");
        using DekRotationBackgroundService service = _harness.CreateService(
            RotationServiceHarness.FastOptions(maxDekAge: TimeSpan.FromHours(1), maxRetriesPerScope: 2));

        Func<Task> act = () => service.RunTickAsync(CancellationToken.None);

        await act.Should().NotThrowAsync("a scope failing after retries is logged, never propagated out of the tick");
        // 1 initial attempt + 2 retries, then give up until the next tick.
        _harness.DekManager.RotateAttempts.Should().HaveCount(3);
    }

    [Fact]
    public async Task RunTickAsync_ZeroMaxRetries_MakesExactlyOneAttempt()
    {
        _harness.Store.SetActiveKey("tenant:once", DateTimeOffset.UtcNow - TimeSpan.FromHours(2));
        _harness.DekManager.AlwaysFail("tenant:once");
        using DekRotationBackgroundService service = _harness.CreateService(
            RotationServiceHarness.FastOptions(maxDekAge: TimeSpan.FromHours(1), maxRetriesPerScope: 0));

        await service.RunTickAsync(CancellationToken.None);

        _harness.DekManager.RotateAttempts.Should().HaveCount(1);
    }

    [Fact]
    public async Task RunTickAsync_OneScopeFailing_DoesNotAbortRemainingScopes()
    {
        DateTimeOffset old = DateTimeOffset.UtcNow - TimeSpan.FromHours(2);
        _harness.Store.SetActiveKey("tenant:broken", old);
        _harness.Store.SetActiveKey("tenant:healthy", old);
        _harness.DekManager.AlwaysFail("tenant:broken");
        using DekRotationBackgroundService service = _harness.CreateService(
            RotationServiceHarness.FastOptions(maxDekAge: TimeSpan.FromHours(1), maxRetriesPerScope: 1));

        await service.RunTickAsync(CancellationToken.None);

        _harness.DekManager.RotateAttempts.Should().Contain("tenant:healthy",
            "a scope failing all its retries must never prevent the rotation of the other scopes");
        _harness.DekManager.RotateAttempts.Count(scope => scope == "tenant:broken").Should().Be(2,
            "1 attempt + 1 retry for the broken scope");
        _harness.DekManager.RotateAttempts.Count(scope => scope == "tenant:healthy").Should().Be(1);
    }

    [Fact]
    public async Task RunTickAsync_CancelledToken_PropagatesCancellation()
    {
        _harness.Store.SetActiveKey("tenant:any", DateTimeOffset.UtcNow - TimeSpan.FromHours(2));
        using DekRotationBackgroundService service = _harness.CreateService(
            RotationServiceHarness.FastOptions(maxDekAge: TimeSpan.FromHours(1)));
        using CancellationTokenSource cts = new();
        await cts.CancelAsync();

        Func<Task> act = () => service.RunTickAsync(cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
        _harness.DekManager.RotateAttempts.Should().BeEmpty();
    }

    [Fact]
    public async Task ExecuteAsync_RotatesOldKey_AndStopsGracefully()
    {
        _harness.Store.SetActiveKey("tenant:exec", DateTimeOffset.UtcNow - TimeSpan.FromHours(2));
        RotationOptions options = RotationServiceHarness.FastOptions(maxDekAge: TimeSpan.FromHours(1));
        options.RotationInterval = TimeSpan.FromMinutes(10); // never reached: we stop after the first tick
        using DekRotationBackgroundService service = _harness.CreateService(options);

        await service.StartAsync(CancellationToken.None);
        Task winner = await Task.WhenAny(
            _harness.DekManager.FirstSuccessfulRotation,
            Task.Delay(TimeSpan.FromSeconds(10)));
        await service.StopAsync(CancellationToken.None);

        winner.Should().Be(_harness.DekManager.FirstSuccessfulRotation,
            "with a zero startup delay the first tick must rotate the old key promptly");
        _harness.DekManager.RotateAttempts.Should().Contain("tenant:exec");
    }

    [Fact]
    public async Task ExecuteAsync_HonorsStartupDelay_NoTickBeforeItElapses()
    {
        _harness.Store.SetActiveKey("tenant:boot", DateTimeOffset.UtcNow - TimeSpan.FromHours(2));
        RotationOptions options = RotationServiceHarness.FastOptions(maxDekAge: TimeSpan.FromHours(1));
        options.StartupDelay = TimeSpan.FromMinutes(10);
        using DekRotationBackgroundService service = _harness.CreateService(options);

        await service.StartAsync(CancellationToken.None);
        await Task.Delay(TimeSpan.FromMilliseconds(200));
        await service.StopAsync(CancellationToken.None);

        _harness.Store.GetActiveScopesCalls.Should().Be(0,
            "no tick may run before the startup delay elapses (don't hammer the KEK provider at boot)");
        _harness.DekManager.RotateAttempts.Should().BeEmpty();
    }
}
