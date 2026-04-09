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
/// </remarks>
/// <param name="Ciphertext">Provider-specific wrapped-DEK ciphertext. Opaque to Vellum core.</param>
/// <param name="ProviderVersion">The version of the KEK used to wrap. Providers that rotate KEKs use this to locate the correct unwrap key.</param>
public sealed record WrappedKey(string Ciphertext, int ProviderVersion);
