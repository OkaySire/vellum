namespace Vellum.Vault.Internal;

/// <summary>
/// Derives the standard-resilience-handler timeouts from <see cref="VaultOptions.HttpTimeout"/>
/// so the pipeline stays coherent with the user's intent for any supplied timeout.
/// </summary>
/// <remarks>
/// <para>
/// The standard resilience handler validates its options
/// (<c>StandardResilienceOptionsCustomValidator</c> + data annotations):
/// </para>
/// <list type="bullet">
///   <item><description><c>TotalRequestTimeout.Timeout ≥ AttemptTimeout.Timeout</c>.</description></item>
///   <item><description><c>CircuitBreaker.SamplingDuration ≥ 2 × AttemptTimeout.Timeout</c>.</description></item>
///   <item><description>Timeouts are bounded to at most 1 day; sampling duration at least 500 ms.</description></item>
/// </list>
/// <para>
/// The derivations below satisfy all of these for any positive <c>HttpTimeout</c>:
/// the per-attempt timeout is the user's <c>HttpTimeout</c> (clamped into the valid range,
/// capped at 12 h so that twice its value still fits the 1-day sampling ceiling), the total
/// timeout budgets one initial attempt plus three retries plus a worst-case exponential
/// backoff allowance, and the sampling duration is exactly the validator's lower bound,
/// floored at the handler's 30 s default.
/// </para>
/// </remarks>
internal static class VaultResilienceTimeouts
{
    private static readonly TimeSpan _minAttemptTimeout = TimeSpan.FromMilliseconds(10);
    private static readonly TimeSpan _maxAttemptTimeout = TimeSpan.FromHours(12);
    private static readonly TimeSpan _maxTimeout = TimeSpan.FromDays(1);
    private static readonly TimeSpan _minSamplingDuration = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Worst-case allowance for the standard handler's retry backoff (exponential, 2 s base,
    /// jittered: ~2 + 4 + 8 s for three retries, rounded up generously).
    /// </summary>
    private static readonly TimeSpan _retryBackoffAllowance = TimeSpan.FromSeconds(20);

    /// <summary>The per-attempt timeout: the user's <c>HttpTimeout</c>, clamped into range.</summary>
    internal static TimeSpan AttemptTimeout(TimeSpan httpTimeout) =>
        Clamp(httpTimeout, _minAttemptTimeout, _maxAttemptTimeout);

    /// <summary>
    /// The overall deadline: 4 attempts (1 initial + 3 retries) plus the backoff allowance,
    /// capped at the handler's 1-day maximum.
    /// </summary>
    internal static TimeSpan TotalRequestTimeout(TimeSpan httpTimeout)
    {
        TimeSpan attempt = AttemptTimeout(httpTimeout);
        double totalMs = (attempt.TotalMilliseconds * 4) + _retryBackoffAllowance.TotalMilliseconds;
        return Clamp(TimeSpan.FromMilliseconds(totalMs), attempt, _maxTimeout);
    }

    /// <summary>
    /// The circuit-breaker sampling window: the validator's lower bound (2 × attempt timeout),
    /// floored at the standard handler's 30 s default.
    /// </summary>
    internal static TimeSpan CircuitBreakerSamplingDuration(TimeSpan httpTimeout)
    {
        TimeSpan attempt = AttemptTimeout(httpTimeout);
        TimeSpan twiceAttempt = TimeSpan.FromMilliseconds(attempt.TotalMilliseconds * 2);
        return Clamp(twiceAttempt, _minSamplingDuration, _maxTimeout);
    }

    private static TimeSpan Clamp(TimeSpan value, TimeSpan min, TimeSpan max) =>
        value < min ? min : value > max ? max : value;
}
