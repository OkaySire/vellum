namespace Vellum.Static;

/// <summary>
/// Configuration for the static-key KEK provider.
/// </summary>
/// <remarks>
/// <para>
/// <b>⚠️ DEVELOPMENT USE ONLY ⚠️</b>
/// </para>
/// <para>
/// These options carry a raw AES-256 Key Encryption Key in configuration. The provider exists
/// for local development, tests, and samples. It is <b>never</b> safe for production because
/// the KEK has exactly the same security as the configuration file, environment variable, or
/// secret store it was loaded from — and those surfaces almost always leak into logs, crash
/// dumps, CI artefacts, or developer workstations.
/// </para>
/// <para>
/// For production, use a real KEK provider: <c>Vellum.Vault</c>, <c>Vellum.AzureKeyVault</c>,
/// <c>Vellum.AwsKms</c>, or <c>Vellum.GcpKms</c>.
/// </para>
/// </remarks>
public sealed class StaticOptions
{
    /// <summary>
    /// Gets or sets the base64-encoded 32-byte (AES-256) Key Encryption Key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Must decode to exactly 32 bytes. Generate a suitable value with, for example,
    /// <c>openssl rand -base64 32</c> or the .NET equivalent
    /// <c>Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))</c>.
    /// </para>
    /// <para>
    /// <b>Secret.</b> Vellum never logs this value, never serialises it, and never includes it
    /// in exception or validation messages — but its security is only as strong as the config
    /// source it came from. Treat the config file the same way you would treat the raw key.
    /// </para>
    /// </remarks>
    public string Base64Key { get; set; } = string.Empty;
}
