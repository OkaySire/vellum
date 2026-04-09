namespace Vellum;

/// <summary>
/// Configuration for Vellum core services.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="VellumOptions"/> covers the options consumed by <see cref="DekManager"/> and
/// <see cref="PayloadEncryptor"/>. Provider-specific options (for example, Vault address,
/// AWS KMS key ARN) live in the corresponding provider package's own options type.
/// </para>
/// <para>
/// Rotation is opt-in and lives in <c>Vellum.Rotation</c>; that package exposes its own
/// <c>RotationOptions</c> type and never reads from <see cref="VellumOptions"/>.
/// </para>
/// </remarks>
public sealed class VellumOptions
{
    /// <summary>
    /// How long an unwrapped Data Encryption Key may live in the in-memory cache before being
    /// evicted. Defaults to 30 minutes.
    /// </summary>
    /// <remarks>
    /// Shorter TTLs reduce the window during which a plaintext DEK is held in process memory,
    /// at the cost of more frequent KEK provider round-trips. Set to <see cref="TimeSpan.Zero"/>
    /// or a negative value to disable caching entirely.
    /// </remarks>
    public TimeSpan DekCacheTtl { get; set; } = TimeSpan.FromMinutes(30);
}
