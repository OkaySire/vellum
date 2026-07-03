using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Vellum.Rotation;

/// <summary>
/// Opt-in hosted service that periodically rotates Data Encryption Keys whose active key is older
/// than <see cref="RotationOptions.MaxDekAge"/>, scope by scope.
/// </summary>
/// <remarks>
/// <para>
/// <b>Tick anatomy.</b> Every <see cref="RotationOptions.RotationInterval"/> the worker resolves a
/// fresh DI scope (so EF-Core-backed <see cref="IEncryptionKeyStore"/> implementations get their
/// scoped <c>DbContext</c>), lists the scopes with an active key via
/// <see cref="IEncryptionKeyStore.GetActiveScopesAsync"/>, and for each scope reads the active key
/// and rotates it via <see cref="IDekManager.RotateDekAsync"/> only when the key's age has reached
/// <see cref="RotationOptions.MaxDekAge"/>. Young keys are skipped — no KEK-provider round-trip.
/// </para>
/// <para>
/// <b>Failure isolation.</b> A scope that still fails after
/// <see cref="RotationOptions.MaxRetriesPerScope"/> retries (exponential backoff with jitter,
/// inside the same tick) is logged as an error and the tick moves on to the next scope. Rotation
/// itself is fail-safe: <see cref="IDekManager.RotateDekAsync"/> leaves the previously-active key
/// active when the KEK provider or the store fails, so encrypts keep working on the old key until
/// the next attempt.
/// </para>
/// <para>
/// <b>Clocks and delays.</b> Both the key-age computation and every delay (startup, interval,
/// backoff) go through the injected <see cref="TimeProvider"/>
/// (<c>Task.Delay(delay, timeProvider, token)</c>), so tests can substitute a fake provider.
/// </para>
/// </remarks>
public sealed partial class DekRotationBackgroundService(
    IServiceScopeFactory scopeFactory,
    TimeProvider timeProvider,
    IOptions<RotationOptions> options,
    ILogger<DekRotationBackgroundService> logger) : BackgroundService
{
    /// <summary>
    /// Exponent clamp for the backoff computation so that <c>2^attempt</c> can never overflow
    /// or produce absurd delays regardless of <see cref="RotationOptions.MaxRetriesPerScope"/>.
    /// </summary>
    private const int MaxBackoffExponent = 10;

    /// <summary>
    /// Hard ceiling on a single backoff delay (5 minutes). A retry loop must never park a tick
    /// for longer than this between two attempts on the same scope.
    /// </summary>
    private const double MaxBackoffMilliseconds = 5d * 60d * 1000d;

    private readonly IServiceScopeFactory _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly RotationOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
    private readonly ILogger<DekRotationBackgroundService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        LogServiceStarted(_logger, _options.RotationInterval, _options.MaxDekAge, _options.StartupDelay);

        try
        {
            if (_options.StartupDelay > TimeSpan.Zero)
            {
                await Task.Delay(_options.StartupDelay, _timeProvider, stoppingToken).ConfigureAwait(false);
            }

            while (!stoppingToken.IsCancellationRequested)
            {
                await RunTickAsync(stoppingToken).ConfigureAwait(false);
                await Task.Delay(_options.RotationInterval, _timeProvider, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Graceful shutdown: the host cancelled the stopping token. This is the only
            // condition the filter matches — any other exception still propagates and is
            // surfaced by the host's BackgroundServiceExceptionBehavior.
            LogServiceStopping(_logger);
        }
    }

    /// <summary>
    /// Runs a single rotation tick: lists active scopes, skips scopes whose active key is younger
    /// than <see cref="RotationOptions.MaxDekAge"/>, and rotates the rest with per-scope retry.
    /// </summary>
    /// <remarks>
    /// Internal (rather than folded into <see cref="ExecuteAsync"/>) so that tests can drive one
    /// tick deterministically without timers — see <c>Vellum.Rotation.Tests</c>.
    /// </remarks>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Deliberate per-scope failure isolation: one scope failing its rotation (after retries) must never abort the rotation of the remaining scopes. The exception is logged as an error with full detail; cancellation is re-thrown by the preceding filter.")]
    internal async Task RunTickAsync(CancellationToken cancellationToken)
    {
        using IServiceScope serviceScope = _scopeFactory.CreateScope();
        IEncryptionKeyStore store = serviceScope.ServiceProvider.GetRequiredService<IEncryptionKeyStore>();
        IDekManager dekManager = serviceScope.ServiceProvider.GetRequiredService<IDekManager>();

        IReadOnlyList<string> scopes = await store.GetActiveScopesAsync(cancellationToken).ConfigureAwait(false);
        LogTickStarted(_logger, scopes.Count);

        int rotated = 0;
        int skipped = 0;
        int failed = 0;

        foreach (string scope in scopes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                bool didRotate = await ProcessScopeAsync(store, dekManager, scope, cancellationToken).ConfigureAwait(false);
                if (didRotate)
                {
                    rotated++;
                }
                else
                {
                    skipped++;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                failed++;
                LogScopeFailed(_logger, scope, _options.MaxRetriesPerScope + 1, ex);
            }
        }

        LogTickCompleted(_logger, rotated, skipped, failed);
    }

    /// <summary>
    /// Examines one scope: skips it when the active key is missing or younger than
    /// <see cref="RotationOptions.MaxDekAge"/>, otherwise rotates with retry.
    /// </summary>
    /// <returns><see langword="true"/> when the scope was rotated, <see langword="false"/> when it was skipped.</returns>
    private async Task<bool> ProcessScopeAsync(
        IEncryptionKeyStore store,
        IDekManager dekManager,
        string scope,
        CancellationToken cancellationToken)
    {
        EncryptionKey? active = await store.GetActiveAsync(scope, cancellationToken).ConfigureAwait(false);
        if (active is null)
        {
            // The scope lost its active key between GetActiveScopesAsync and now (for example,
            // an administrative DeactivateAllAsync). There is nothing to rotate — creating a key
            // here would silently undo the revocation, so skip instead.
            LogScopeSkippedNoActiveKey(_logger, scope);
            return false;
        }

        TimeSpan age = _timeProvider.GetUtcNow() - active.CreatedAt;
        if (age < _options.MaxDekAge)
        {
            LogScopeSkippedYoungKey(_logger, scope, age, _options.MaxDekAge);
            return false;
        }

        await RotateWithRetryAsync(dekManager, scope, cancellationToken).ConfigureAwait(false);
        LogScopeRotated(_logger, scope, age);
        return true;
    }

    /// <summary>
    /// Calls <see cref="IDekManager.RotateDekAsync"/> with up to
    /// <see cref="RotationOptions.MaxRetriesPerScope"/> retries inside the current tick, waiting
    /// an exponentially increasing, jittered delay between attempts. The final failure propagates
    /// to the per-scope catch in <see cref="RunTickAsync"/>.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Retry boundary: any rotation failure (KEK provider, store, network) is retried with backoff while attempts remain — the filter rethrows once retries are exhausted, and cancellation is re-thrown by the preceding filter. Nothing is swallowed.")]
    private async Task RotateWithRetryAsync(IDekManager dekManager, string scope, CancellationToken cancellationToken)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                await dekManager.RotateDekAsync(scope, cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (attempt < _options.MaxRetriesPerScope)
            {
                TimeSpan delay = ComputeBackoffDelay(attempt);
                LogScopeRetryScheduled(_logger, scope, attempt + 1, _options.MaxRetriesPerScope, delay, ex);
                await Task.Delay(delay, _timeProvider, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Equal-jitter exponential backoff: half of <c>RetryBaseDelay × 2^attempt</c> deterministic,
    /// half random. The jitter desynchronises multiple worker replicas so a KEK-provider recovery
    /// is not greeted by a synchronized retry stampede.
    /// </summary>
    /// <remarks>
    /// Uses <see cref="RandomNumberGenerator"/> rather than <see cref="Random"/> — the jitter is
    /// not security-sensitive, but CSPRNG keeps the analyzers (CA5394) satisfied at zero practical
    /// cost on a path that is about to wait for seconds anyway.
    /// </remarks>
    private TimeSpan ComputeBackoffDelay(int attempt)
    {
        double exponentialMs = _options.RetryBaseDelay.TotalMilliseconds * Math.Pow(2d, Math.Min(attempt, MaxBackoffExponent));
        double cappedMs = Math.Min(exponentialMs, MaxBackoffMilliseconds);
        double halfMs = cappedMs / 2d;
        int jitterMs = halfMs >= 1d ? RandomNumberGenerator.GetInt32(0, (int)halfMs + 1) : 0;
        return TimeSpan.FromMilliseconds(halfMs + jitterMs);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "DEK rotation service started (interval: {Interval}, max DEK age: {MaxDekAge}, startup delay: {StartupDelay})")]
    private static partial void LogServiceStarted(ILogger logger, TimeSpan interval, TimeSpan maxDekAge, TimeSpan startupDelay);

    [LoggerMessage(Level = LogLevel.Information, Message = "DEK rotation service stopping")]
    private static partial void LogServiceStopping(ILogger logger);

    [LoggerMessage(Level = LogLevel.Information, Message = "DEK rotation tick started for {ScopeCount} scope(s)")]
    private static partial void LogTickStarted(ILogger logger, int scopeCount);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DEK rotation skipped for scope {Scope}: no active key (revoked since scope listing)")]
    private static partial void LogScopeSkippedNoActiveKey(ILogger logger, string scope);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DEK rotation skipped for scope {Scope}: active key age {Age} is below the maximum DEK age {MaxDekAge}")]
    private static partial void LogScopeSkippedYoungKey(ILogger logger, string scope, TimeSpan age, TimeSpan maxDekAge);

    [LoggerMessage(Level = LogLevel.Information, Message = "DEK rotated for scope {Scope} (previous key age: {Age})")]
    private static partial void LogScopeRotated(ILogger logger, string scope, TimeSpan age);

    [LoggerMessage(Level = LogLevel.Warning, Message = "DEK rotation attempt {Attempt}/{MaxRetries} failed for scope {Scope}; retrying in {Delay}")]
    private static partial void LogScopeRetryScheduled(ILogger logger, string scope, int attempt, int maxRetries, TimeSpan delay, Exception ex);

    [LoggerMessage(Level = LogLevel.Error, Message = "DEK rotation failed for scope {Scope} after {Attempts} attempt(s); the previously-active key remains active, next attempt on the next tick")]
    private static partial void LogScopeFailed(ILogger logger, string scope, int attempts, Exception ex);

    [LoggerMessage(Level = LogLevel.Information, Message = "DEK rotation tick completed: {Rotated} rotated, {Skipped} skipped, {Failed} failed")]
    private static partial void LogTickCompleted(ILogger logger, int rotated, int skipped, int failed);
}
