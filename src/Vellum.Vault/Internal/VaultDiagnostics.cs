using System.Globalization;

namespace Vellum.Vault.Internal;

/// <summary>
/// Shared helpers for embedding Vault error responses in diagnostics without amplifying
/// attacker-controlled content.
/// </summary>
internal static class VaultDiagnostics
{
    /// <summary>
    /// H-2: hard cap on the number of chars copied from a Vault error response body into log
    /// entries and exception messages. A malicious or misconfigured Vault (or an interposing
    /// proxy echoing arbitrary content) could otherwise return megabytes of attacker-controlled
    /// content that would be embedded verbatim in logs and exceptions.
    /// </summary>
    private const int _errorBodyTruncateChars = 512;

    /// <summary>
    /// H-2: truncates an error body to a small, fixed upper bound before embedding it in log
    /// entries or exception messages. The truncation is by char count, not byte count, which
    /// is safe because the result is only used for human-facing diagnostics — never for
    /// semantic parsing. The explicit "[truncated, N chars]" suffix makes it obvious to
    /// operators that content was elided.
    /// </summary>
    internal static string TruncateForDiagnostics(string body)
    {
        if (string.IsNullOrEmpty(body))
        {
            return string.Empty;
        }

        if (body.Length <= _errorBodyTruncateChars)
        {
            return body;
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{body.AsSpan(0, _errorBodyTruncateChars)}... [truncated, original length {body.Length} chars]");
    }
}
