namespace Vellum.Samples.FeatureFlagged;

/// <summary>
/// Consumer-owned feature-flag POCO. Normally bound to configuration (appsettings.json
/// or a remote flag store) via <c>services.Configure&lt;FeatureFlags&gt;(...)</c>.
/// </summary>
public sealed class FeatureFlags
{
    /// <summary>
    /// Master switch for envelope encryption. When <see langword="false"/>, the
    /// <see cref="FeatureFlaggedPayloadEncryptor"/> short-circuits Encrypt/Decrypt to
    /// plaintext passthrough so a staged rollout can flip traffic on and off without
    /// touching the DI container.
    /// </summary>
    public bool EncryptionEnabled { get; set; } = true;
}
