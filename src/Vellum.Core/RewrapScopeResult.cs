namespace Vellum;

/// <summary>
/// Outcome of a <see cref="VellumRewrapService.RewrapStoredKeysAsync(string, CancellationToken)"/>
/// sweep over one scope's stored keys.
/// </summary>
/// <remarks>
/// <para>
/// This type lives in <c>Vellum.Core</c> (not <c>Vellum.Abstractions</c>) deliberately: it is the
/// result DTO of the Core-owned orchestrator, not a contract that providers or stores implement.
/// Keeping it next to <see cref="VellumRewrapService"/> avoids growing the abstractions surface
/// for a type nothing else needs to reference.
/// </para>
/// <para>
/// A sweep with <see cref="Failed"/> &gt; 0 does <b>not</b> throw — each failure is logged and
/// recorded in <see cref="FailedKeyIds"/>, and the caller decides whether to retry. Rewrapping is
/// idempotent (rewrapping an already-current wrapped key is a version-level no-op), so re-running
/// the sweep until <see cref="Failed"/> reaches zero is always safe.
/// </para>
/// </remarks>
/// <param name="Total">Number of distinct keys (active and historical) found for the scope.</param>
/// <param name="Rewrapped">Number of keys successfully rewrapped and persisted.</param>
/// <param name="Failed">Number of keys whose rewrap or persistence failed. Always equals <c>Total - Rewrapped</c>.</param>
/// <param name="FailedKeyIds">Identifiers of the keys that failed, for targeted retry or investigation.</param>
public sealed record RewrapScopeResult(
    int Total,
    int Rewrapped,
    int Failed,
    IReadOnlyList<Guid> FailedKeyIds);
