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

    /// <summary>
    /// Gets or sets a value indicating whether a plain <c>http://</c> <see cref="Address"/> is
    /// permitted. Defaults to <see langword="false"/>: an <c>http://</c> address fails validation
    /// and the host refuses to start.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>DANGER — never enable this in production.</b> Over plain HTTP, every Vault Transit
    /// request transmits the <see cref="Token"/> (<c>X-Vault-Token</c> header) <b>and</b> the
    /// base64-encoded plaintext DEK (encrypt request body / decrypt response body) in cleartext.
    /// Anyone on the network path can capture the token and every data encryption key, defeating
    /// envelope encryption entirely.
    /// </para>
    /// <para>
    /// The only legitimate use is local development against an ephemeral dev server
    /// (<c>vault server -dev</c> on <c>127.0.0.1</c>). When enabled with an <c>http://</c>
    /// address, Vellum logs a <see cref="Microsoft.Extensions.Logging.LogLevel.Warning"/> each
    /// time a Vault <see cref="HttpClient"/> is constructed so the insecure configuration is
    /// impossible to miss in logs.
    /// </para>
    /// </remarks>
    public bool AllowInsecureHttp { get; set; }
}
