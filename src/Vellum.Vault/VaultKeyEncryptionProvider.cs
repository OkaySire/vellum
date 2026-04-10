using System.Globalization;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Vellum.Vault.Internal;

namespace Vellum.Vault;

/// <summary>
/// An <see cref="IKeyEncryptionProvider"/> that wraps and unwraps Data Encryption Keys via the
/// HashiCorp Vault Transit secrets engine.
/// </summary>
/// <remarks>
/// <para>
/// <b>Backend contract.</b> This provider calls the Vault Transit HTTP API:
/// </para>
/// <list type="bullet">
///   <item><description><c>POST /v1/transit/encrypt/{key}</c> — wraps a DEK, returns <c>vault:v{N}:…</c>.</description></item>
///   <item><description><c>POST /v1/transit/decrypt/{key}</c> — unwraps a previously-wrapped DEK.</description></item>
/// </list>
/// <para>
/// <b>Provider version.</b> The version segment of the Vault ciphertext (e.g. <c>v1</c>, <c>v2</c>)
/// is extracted and stored verbatim in <see cref="WrappedKey.ProviderVersion"/> to preserve the
/// Vault semantic without losing information. Vellum never parses this field downstream — it is
/// only round-tripped for operational visibility and audits.
/// </para>
/// <para>
/// <b>Fail closed (L6).</b> Every failure path — HTTP error, non-2xx status, malformed JSON,
/// malformed base64, missing ciphertext or plaintext — throws. The provider never returns
/// <see langword="null"/>, empty bytes, or the original plaintext on error.
/// </para>
/// <para>
/// <b>HttpClient lifetime.</b> The <see cref="HttpClient"/> is supplied by
/// <see cref="IHttpClientFactory"/> via the typed-client registration in
/// <c>VaultServiceCollectionExtensions.AddVaultProvider</c>. The base address, timeout, and
/// <c>X-Vault-Token</c> header are all configured there; this class only issues relative requests.
/// </para>
/// </remarks>
public sealed partial class VaultKeyEncryptionProvider(
    HttpClient httpClient,
    IOptions<VaultOptions> options,
    ILogger<VaultKeyEncryptionProvider> logger) : IKeyEncryptionProvider
{
    private const string _vaultCiphertextPrefix = "vault:v";

    /// <summary>
    /// H-2: hard cap on the number of bytes copied from a Vault error response body into log
    /// entries and exception messages. A malicious or misconfigured Vault (or an interposing
    /// proxy echoing arbitrary content) could otherwise return megabytes of attacker-controlled
    /// content that would be embedded verbatim in logs and exceptions.
    /// </summary>
    private const int _errorBodyTruncateBytes = 512;

    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    private readonly VaultOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly ILogger<VaultKeyEncryptionProvider> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    /// <inheritdoc />
    public string ProviderName => "vault";

    /// <inheritdoc />
    public async Task<WrappedKey> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken cancellationToken = default)
    {
        if (dek.IsEmpty)
        {
            throw new ArgumentException("DEK must not be empty.", nameof(dek));
        }

        string plaintextBase64 = Convert.ToBase64String(dek.Span);
        VaultEncryptRequest requestDto = new(plaintextBase64);

        using JsonContent content = JsonContent.Create(requestDto, VaultJsonContext.Default.VaultEncryptRequest);
        string relativePath = BuildTransitPath("encrypt");

        using HttpResponseMessage response = await _httpClient
            .PostAsync(new Uri(relativePath, UriKind.Relative), content, cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            string errorBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            string truncatedBody = TruncateForDiagnostics(errorBody);
            LogVaultError(_logger, "encrypt", (int)response.StatusCode, truncatedBody);
            throw new InvalidOperationException(
                $"Vault Transit encrypt failed with HTTP {(int)response.StatusCode} ({response.StatusCode}): {truncatedBody}");
        }

        VaultEncryptResponse? parsed;
        try
        {
            parsed = await response.Content
                .ReadFromJsonAsync(VaultJsonContext.Default.VaultEncryptResponse, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (JsonException ex)
        {
            LogJsonParseFailed(_logger, "encrypt", ex.Message);
            throw;
        }

        string? ciphertext = parsed?.Data?.Ciphertext;
        if (string.IsNullOrEmpty(ciphertext))
        {
            throw new InvalidOperationException("Vault Transit encrypt returned a null or empty ciphertext.");
        }

        string providerVersion = ExtractProviderVersion(ciphertext);

        LogEncryptSucceeded(_logger, _options.KeyName, providerVersion);
        return new WrappedKey(ciphertext, providerVersion);
    }

    /// <inheritdoc />
    public async Task<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);

        if (string.IsNullOrEmpty(wrappedKey.Ciphertext))
        {
            throw new ArgumentException("WrappedKey.Ciphertext must not be null or empty.", nameof(wrappedKey));
        }

        // Sanity-check the format before we even make the HTTP call — fail fast, fail closed.
        if (!wrappedKey.Ciphertext.StartsWith(_vaultCiphertextPrefix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"WrappedKey.Ciphertext does not start with '{_vaultCiphertextPrefix}'; this provider only unwraps Vault-formatted ciphertexts.");
        }

        VaultDecryptRequest requestDto = new(wrappedKey.Ciphertext);
        using JsonContent content = JsonContent.Create(requestDto, VaultJsonContext.Default.VaultDecryptRequest);
        string relativePath = BuildTransitPath("decrypt");

        using HttpResponseMessage response = await _httpClient
            .PostAsync(new Uri(relativePath, UriKind.Relative), content, cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            string errorBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            string truncatedBody = TruncateForDiagnostics(errorBody);
            LogVaultError(_logger, "decrypt", (int)response.StatusCode, truncatedBody);
            throw new InvalidOperationException(
                $"Vault Transit decrypt failed with HTTP {(int)response.StatusCode} ({response.StatusCode}): {truncatedBody}");
        }

        VaultDecryptResponse? parsed;
        try
        {
            parsed = await response.Content
                .ReadFromJsonAsync(VaultJsonContext.Default.VaultDecryptResponse, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (JsonException ex)
        {
            LogJsonParseFailed(_logger, "decrypt", ex.Message);
            throw;
        }

        string? plaintextBase64 = parsed?.Data?.Plaintext;
        if (string.IsNullOrEmpty(plaintextBase64))
        {
            throw new InvalidOperationException("Vault Transit decrypt returned a null or empty plaintext.");
        }

        byte[] dekBytes;
        try
        {
            dekBytes = Convert.FromBase64String(plaintextBase64);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("Vault Transit decrypt returned malformed base64 plaintext.", ex);
        }

        LogDecryptSucceeded(_logger, _options.KeyName);
        return dekBytes;
    }

    /// <summary>
    /// H-2: truncates an error body to a small, fixed upper bound before embedding it in log
    /// entries or exception messages. The truncation is by char count, not byte count, which
    /// is safe because we are only using the result for human-facing diagnostics — never for
    /// semantic parsing. The explicit "[truncated, N chars]" suffix makes it obvious to
    /// operators that content was elided.
    /// </summary>
    private static string TruncateForDiagnostics(string body)
    {
        if (string.IsNullOrEmpty(body))
        {
            return string.Empty;
        }

        if (body.Length <= _errorBodyTruncateBytes)
        {
            return body;
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{body.AsSpan(0, _errorBodyTruncateBytes)}... [truncated, original length {body.Length} chars]");
    }

    /// <summary>
    /// Builds the relative transit-engine URL for a given operation, URL-encoding the key name
    /// so that names with reserved characters are transmitted safely.
    /// </summary>
    private string BuildTransitPath(string operation)
    {
        return string.Create(
            CultureInfo.InvariantCulture,
            $"v1/transit/{operation}/{Uri.EscapeDataString(_options.KeyName)}");
    }

    /// <summary>
    /// Extracts the provider version segment ("v{N}") from a Vault Transit ciphertext of the
    /// form <c>vault:v{N}:{base64}</c>. Uses explicit bounds rather than a fragile
    /// <c>IndexOf</c>-split so that malformed inputs throw rather than silently truncate.
    /// </summary>
    private static string ExtractProviderVersion(string ciphertext)
    {
        // Caller already verified the prefix in the Wrap path via the response shape, but Unwrap
        // also validates before calling — keep this assertion local so the method is usable
        // independently of the call site.
        if (!ciphertext.StartsWith(_vaultCiphertextPrefix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Vault ciphertext does not start with '{_vaultCiphertextPrefix}'.");
        }

        int versionStart = _vaultCiphertextPrefix.Length;
        int versionEnd = ciphertext.IndexOf(':', versionStart);
        if (versionEnd <= versionStart)
        {
            throw new InvalidOperationException(
                "Vault ciphertext is missing the ':' delimiter after the version segment.");
        }

        ReadOnlySpan<char> versionSpan = ciphertext.AsSpan(versionStart, versionEnd - versionStart);
        if (!int.TryParse(versionSpan, NumberStyles.Integer, CultureInfo.InvariantCulture, out int version) || version < 1)
        {
            throw new InvalidOperationException(
                $"Vault ciphertext version segment '{versionSpan.ToString()}' is not a positive integer.");
        }

        return "v" + version.ToString(CultureInfo.InvariantCulture);
    }

    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Debug,
        Message = "Vault Transit encrypt succeeded for key {KeyName} (provider version {ProviderVersion}).")]
    private static partial void LogEncryptSucceeded(ILogger logger, string keyName, string providerVersion);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Debug,
        Message = "Vault Transit decrypt succeeded for key {KeyName}.")]
    private static partial void LogDecryptSucceeded(ILogger logger, string keyName);

    [LoggerMessage(
        EventId = 3,
        Level = LogLevel.Error,
        Message = "Vault Transit {Operation} failed with HTTP {StatusCode}: {ErrorBody}")]
    private static partial void LogVaultError(ILogger logger, string operation, int statusCode, string errorBody);

    [LoggerMessage(
        EventId = 4,
        Level = LogLevel.Error,
        Message = "Vault Transit {Operation} response JSON could not be parsed: {ErrorMessage}")]
    private static partial void LogJsonParseFailed(ILogger logger, string operation, string errorMessage);
}
