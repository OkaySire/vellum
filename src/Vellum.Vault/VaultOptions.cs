namespace Vellum.Vault;

/// <summary>
/// Configuration for the HashiCorp Vault Transit key encryption provider.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Address"/> and <see cref="KeyName"/> are always required. The auth fields depend
/// on <see cref="AuthMethod"/>: <see cref="VaultAuthMethod.Token"/> requires <see cref="Token"/>
/// (and <see cref="RoleId"/>/<see cref="SecretId"/> must be empty);
/// <see cref="VaultAuthMethod.AppRole"/> requires <see cref="RoleId"/> and <see cref="SecretId"/>
/// (and <see cref="Token"/> must be empty). Everything is validated at application start-up via
/// <c>ValidateOnStart()</c> — a misconfiguration fails fast rather than surfacing as an obscure
/// runtime error.
/// </para>
/// <para>
/// The <see cref="Token"/> and <see cref="SecretId"/> values are secret: Vellum never logs them
/// and consumers must ensure they are loaded from a secure source (environment variable,
/// Kubernetes secret, or similar) — never hard-coded and never written to the repository.
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
    /// an <c>hvs.*</c> bearer token issued by Vault. Required when <see cref="AuthMethod"/> is
    /// <see cref="VaultAuthMethod.Token"/>; must be empty when it is
    /// <see cref="VaultAuthMethod.AppRole"/>.
    /// </summary>
    /// <remarks>
    /// <b>Secret.</b> Never logged, never serialised, never included in exception messages.
    /// </remarks>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the Vault authentication method. Defaults to
    /// <see cref="VaultAuthMethod.Token"/> (a fixed, pre-issued token).
    /// </summary>
    /// <remarks>
    /// Prefer <see cref="VaultAuthMethod.AppRole"/> in production: a static periodic token that
    /// expires causes a silent outage, while AppRole tokens are re-acquired automatically — see
    /// <see cref="AppRoleVaultTokenProvider"/>.
    /// </remarks>
    public VaultAuthMethod AuthMethod { get; set; } = VaultAuthMethod.Token;

    /// <summary>
    /// Gets or sets the mount path of the AppRole auth method, without the <c>auth/</c> prefix
    /// or surrounding slashes — for example, <c>approle</c> (the default) or a nested
    /// <c>team-a/approle</c>. Only used when <see cref="AuthMethod"/> is
    /// <see cref="VaultAuthMethod.AppRole"/>.
    /// </summary>
    public string AppRoleMount { get; set; } = "approle";

    /// <summary>
    /// Gets or sets the AppRole role id. Required when <see cref="AuthMethod"/> is
    /// <see cref="VaultAuthMethod.AppRole"/>; must be empty otherwise.
    /// </summary>
    /// <remarks>Sensitive. Never logged and never included in exception messages.</remarks>
    public string RoleId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the AppRole secret id. Required when <see cref="AuthMethod"/> is
    /// <see cref="VaultAuthMethod.AppRole"/>; must be empty otherwise.
    /// </summary>
    /// <remarks>
    /// <b>Secret.</b> Never logged, never serialised, never included in exception messages.
    /// </remarks>
    public string SecretId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the fraction of an AppRole token's <c>lease_duration</c> after which a
    /// fresh login is performed. Must be in <c>(0, 1]</c>. Defaults to <c>0.8</c> — a token
    /// with a one-hour lease is replaced after 48 minutes, leaving a comfortable margin before
    /// Vault would start answering <c>403</c>.
    /// </summary>
    /// <remarks>
    /// Vellum re-<b>logs-in</b> rather than renewing the existing token
    /// (<c>renew-self</c>): a re-login is stateless and an AppRole login is a cheap single
    /// round-trip — see <see cref="AppRoleVaultTokenProvider"/> for the full rationale.
    /// </remarks>
    public double TokenRenewalThreshold { get; set; } = 0.8;

    /// <summary>
    /// Gets or sets a value indicating whether the standard HTTP resilience handler
    /// (retries on transient failures, circuit breaker, timeouts) wraps every Vault request.
    /// Defaults to <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When enabled, transient failures (HTTP 5xx, 408, 429, timeouts, connection errors) are
    /// retried up to 3 times with exponential backoff. Vault Transit encrypt/decrypt and
    /// AppRole login POSTs are safe to retry. The per-attempt timeout follows
    /// <see cref="HttpTimeout"/> and the overall deadline budgets all attempts plus backoff;
    /// <see cref="HttpClient.Timeout"/> is then set to infinite so the resilience pipeline
    /// owns the deadline. When disabled, <see cref="HttpClient.Timeout"/> =
    /// <see cref="HttpTimeout"/> applies to the single attempt, as in Vellum 0.1.x.
    /// </para>
    /// <para>
    /// This flag decides whether the resilience handler is added to the
    /// <see cref="HttpClient"/> pipeline, which is a registration-time decision: it is honored
    /// only when set inside the <c>configure</c> delegate passed to <c>AddVaultProvider</c>,
    /// not via a later <c>services.Configure&lt;VaultOptions&gt;</c> call.
    /// </para>
    /// </remarks>
    public bool EnableResilience { get; set; } = true;

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
