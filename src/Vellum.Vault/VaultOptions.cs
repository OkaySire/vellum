namespace Vellum.Vault;

/// <summary>
/// Configuration for the HashiCorp Vault Transit key encryption provider.
/// </summary>
/// <remarks>
/// <para>
/// All three string fields (<see cref="Address"/>, <see cref="Token"/>, <see cref="KeyName"/>)
/// are required and are validated at application start-up via <c>ValidateOnStart()</c>. A missing
/// or empty value will cause the host to fail fast rather than surface as an obscure runtime error.
/// </para>
/// <para>
/// The <see cref="Token"/> value is secret: Vellum never logs it and consumers must ensure it
/// is loaded from a secure source (environment variable, Kubernetes secret, or similar) — never
/// hard-coded and never written to the repository.
/// </para>
/// </remarks>
public sealed class VaultOptions
{
    /// <summary>
    /// Gets or sets the base address of the Vault server — for example,
    /// <c>https://vault.example.com:8200</c>.
    /// </summary>
    /// <remarks>
    /// Must be an absolute URI. A trailing slash is optional and is normalised by the HTTP client.
    /// </remarks>
    public string Address { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the Vault auth token used on the <c>X-Vault-Token</c> header — typically
    /// an <c>hvs.*</c> bearer token issued by Vault.
    /// </summary>
    /// <remarks>
    /// <b>Secret.</b> Never logged, never serialised, never included in exception messages.
    /// </remarks>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the name of the Key Encryption Key (KEK) in the Vault Transit secrets engine
    /// — for example, <c>vellum-kek</c>.
    /// </summary>
    /// <remarks>
    /// The Transit engine must already be enabled and the key must exist. Vellum does not create
    /// or manage the KEK itself.
    /// </remarks>
    public string KeyName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the HTTP timeout applied to every Vault Transit request.
    /// </summary>
    /// <remarks>
    /// Defaults to 10 seconds. Increase only if the Vault deployment is known to be slow or
    /// geographically distant; prefer retries orchestrated by the caller over unbounded timeouts.
    /// </remarks>
    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(10);
}
