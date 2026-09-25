namespace Vellum.Vault.Internal;

/// <summary>
/// Shared rules for Vault mount paths, so the start-up validator
/// (<see cref="VaultOptionsValidator"/>) and the request-time path builder in
/// <c>VaultKeyEncryptionProvider.BuildMountPath</c> cannot drift apart.
/// </summary>
internal static class VaultMountPath
{
    /// <summary>
    /// Returns <see langword="true"/> when any segment is <c>.</c> or <c>..</c>.
    /// </summary>
    /// <remarks>
    /// A mount is a secrets-engine name, never a relative path, so a dot segment is always a
    /// configuration error — and never a harmless one: neither <c>.</c> nor <c>..</c> contains a
    /// character that <see cref="Uri.EscapeDataString(string)"/> escapes, so the segment survives escaping
    /// and <see cref="Uri"/> then normalises the path away. Measured on the pre-fix code, a mount
    /// of <c>transit/../auth/token</c> produced a request to
    /// <c>/v1/auth/token/encrypt/{key}</c> — a different Vault endpoint than the one configured.
    /// </remarks>
    public static bool HasRelativeSegment(IReadOnlyList<string> segments)
    {
        ArgumentNullException.ThrowIfNull(segments);

        for (int i = 0; i < segments.Count; i++)
        {
            string segment = segments[i];
            if (string.Equals(segment, ".", StringComparison.Ordinal) ||
                string.Equals(segment, "..", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
