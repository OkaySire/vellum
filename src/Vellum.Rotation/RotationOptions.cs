namespace Vellum.Rotation;

/// <summary>
/// Configuration for the <see cref="DekRotationBackgroundService"/> background DEK rotation worker.
/// </summary>
/// <remarks>
/// <para>
/// All values are validated at application start-up via <c>ValidateOnStart()</c>:
/// <see cref="RotationInterval"/>, <see cref="MaxDekAge"/> and <see cref="RetryBaseDelay"/> must be
/// positive, <see cref="StartupDelay"/> must be non-negative, and <see cref="MaxRetriesPerScope"/>
/// must be zero or greater. A misconfigured host fails fast instead of silently never rotating.
/// </para>
/// <para>
/// <b>Age-gated rotation.</b> Unlike a naive "rotate everything every tick" worker, the service
/// only rotates a scope when its active key's <see cref="EncryptionKey.CreatedAt"/> is older than
/// <see cref="MaxDekAge"/>. This avoids pointless KEK-provider wrap calls for keys that were
/// recently rotated (for example, manually via <see cref="IDekManager.RotateDekAsync"/>) and avoids
/// synchronising the DEK churn of every scope onto the worker's tick schedule.
/// </para>
/// </remarks>
public sealed class RotationOptions
{
    /// <summary>
    /// Gets or sets how often the rotation worker wakes up to examine all active scopes.
    /// Defaults to 24 hours.
    /// </summary>
    /// <remarks>
    /// The interval is measured from the end of one tick to the start of the next, so a slow
    /// tick (many scopes, retries) never causes overlapping ticks. Must be positive.
    /// </remarks>
    public TimeSpan RotationInterval { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Gets or sets the maximum age of an active DEK before the worker rotates it.
    /// Defaults to 24 hours.
    /// </summary>
    /// <remarks>
    /// On each tick, a scope is rotated only if <c>now - CreatedAt</c> of its active key is
    /// greater than or equal to this value; younger keys are skipped. Must be positive.
    /// </remarks>
    public TimeSpan MaxDekAge { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Gets or sets the number of retries attempted per scope <i>within a tick</i> when
    /// <see cref="IDekManager.RotateDekAsync"/> fails. Defaults to 3.
    /// </summary>
    /// <remarks>
    /// A transient KEK-provider blip (Vault restart, network hiccup) must not postpone a scope's
    /// rotation by a full <see cref="RotationInterval"/>. Each retry waits an exponentially
    /// increasing, jittered delay derived from <see cref="RetryBaseDelay"/>. Set to <c>0</c> to
    /// disable retries (one attempt per scope per tick). Must be zero or greater.
    /// </remarks>
    public int MaxRetriesPerScope { get; set; } = 3;

    /// <summary>
    /// Gets or sets the base delay for the per-scope retry backoff. Defaults to 5 seconds.
    /// </summary>
    /// <remarks>
    /// Attempt <c>n</c> (1-based) waits approximately <c>RetryBaseDelay × 2^(n-1)</c>, with
    /// random jitter applied so that multiple replicas of the worker do not hammer the KEK
    /// provider in lock-step. Must be positive.
    /// </remarks>
    public TimeSpan RetryBaseDelay { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Gets or sets the delay before the first tick after the host starts.
    /// Defaults to 1 minute.
    /// </summary>
    /// <remarks>
    /// Application boot is the worst moment to fan out KEK-provider calls — caches are cold and
    /// every request is already racing to unwrap its DEK. The startup delay lets the application
    /// warm up first. May be <see cref="TimeSpan.Zero"/> (start immediately); must not be negative.
    /// </remarks>
    public TimeSpan StartupDelay { get; set; } = TimeSpan.FromMinutes(1);
}
