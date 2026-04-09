namespace Vellum;

/// <summary>
/// The result of wrapping a Data Encryption Key (DEK) with a Key Encryption Key (KEK) via an <see cref="IKeyEncryptionProvider"/>.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="Ciphertext"/> format is provider-specific. For example:
/// </para>
/// <list type="bullet">
///   <item><description><b>HashiCorp Vault Transit</b>: <c>vault:v1:&lt;base64&gt;</c></description></item>
///   <item><description><b>AWS KMS</b>: base64-encoded blob</description></item>
///   <item><description><b>Azure Key Vault</b>: base64-encoded blob</description></item>
///   <item><description><b>GCP KMS</b>: base64-encoded blob</description></item>
/// </list>
/// <para>
/// Consumers should not attempt to parse <see cref="Ciphertext"/>; only the originating provider
/// knows how to interpret it.
/// </para>
/// <para>
/// <see cref="ProviderVersion"/> is an opaque provider-specific string. Cloud providers use
/// heterogeneous formats: HashiCorp Vault returns integers such as <c>"1"</c>, AWS KMS returns
/// ARNs, Azure Key Vault returns key URIs containing a GUID, and GCP KMS returns full resource
/// paths. Vellum never interprets this field — it is round-tripped verbatim to
/// <see cref="IKeyEncryptionProvider.UnwrapAsync(WrappedKey, System.Threading.CancellationToken)"/>.
/// </para>
/// </remarks>
/// <param name="Ciphertext">Provider-specific wrapped-DEK ciphertext. Opaque to Vellum core.</param>
/// <param name="ProviderVersion">Opaque provider-specific version/identifier of the KEK used to wrap. Round-tripped verbatim on unwrap.</param>
public sealed record WrappedKey(string Ciphertext, string ProviderVersion);
