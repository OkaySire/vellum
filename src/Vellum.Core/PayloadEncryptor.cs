using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Vellum;

/// <summary>
/// Default <see cref="IPayloadEncryptor"/> implementation built on AES-256-GCM and envelope
/// encryption. Encryption resolves the active DEK for the given scope via
/// <see cref="IDekManager"/>; decryption resolves the DEK from
/// <see cref="IEncryptionKeyStore"/> by <see cref="EncryptedPayload.KeyId"/> first and falls back
/// to the wrapped DEK copy embedded in the self-contained <see cref="EncryptedPayload"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Store first, envelope copy as a fallback (0.4.0).</b> <see cref="DecryptAsync"/> asks
/// <see cref="IDekManager.GetDekByKeyIdAsync"/> for the DEK behind
/// <see cref="EncryptedPayload.KeyId"/> before looking at
/// <see cref="EncryptedPayload.WrappedDek"/>. The store holds <i>one</i> wrapped-DEK record per
/// key, so rewrapping a DEK against a different KEK (a new Vault Transit mount, a new KMS key)
/// only has to update those records — the envelopes persisted alongside each row do not have to
/// be rewritten, and the order of the two operations stops mattering.
/// </para>
/// <para>
/// <b>What the fallback covers.</b> The envelope's own copy is used when the store cannot serve
/// the key (<i>(a)</i> unknown <see cref="EncryptedPayload.KeyId"/>, scope mismatch, store
/// unreachable) <b>and</b> when the store <i>does</i> return a record but that record fails to
/// unwrap or fails the AES-GCM tag check (<i>(b)</i> a stale or wrong record — the store returns
/// something, not nothing). Case (b) is what keeps the reordering safe: the fallback can only
/// ever turn a failure into a success, never a success into a failure, because every payload that
/// decrypted through the envelope copy in 0.3.x still reaches that copy in 0.4.0.
/// </para>
/// <para>
/// <b>Typed, not textual.</b> The fallback triggers on the <i>type</i> of the failure raised by
/// Vellum's own abstractions (and on AES-GCM's own authentication failure), never on the text of a
/// KEK backend's error response. A wrong-mount Vault reply and a genuinely missing key both return
/// HTTP 400 and differ only in wording, so any detection keyed on that wording would stop firing —
/// silently — the day the backend rephrases it. Resolving from the store first removes the need to
/// tell them apart at all.
/// </para>
/// <para>
/// <b>What this costs (the store dependency).</b> Decryption now depends on
/// <see cref="IEncryptionKeyStore"/>, hence usually on a database. For a backend that has just
/// read the ciphertext out of that same database this is free. It is <b>not</b> free for a consumer
/// decrypting a portable envelope with no store reachable: the store lookup is attempted, throws,
/// and case (b) catches it, so the decrypt still succeeds off the envelope copy — but it pays one
/// wasted round-trip (and, per decrypt, two KEK calls instead of one) before getting there. Such
/// consumers should watch <see cref="VellumDecryptMetrics.FallbackAttemptsTotal"/>. Because the
/// fallback also swallows a store-side scope mismatch, the store lookup adds no cross-tenant
/// control that 0.3.x did not already have: scope binding remains enforced cryptographically by
/// the format version 2 AAD, not by the lookup.
/// </para>
/// <para>
/// <b>Observability.</b> Both paths are instrumented — see <see cref="VellumDecryptMetrics"/> for
/// the gauges that distinguish "still migrating" from "genuinely broken".
/// </para>
/// <para>
/// <b>AES-GCM layout.</b> The <see cref="EncryptedPayload.Ciphertext"/> field stores the raw
/// ciphertext followed by the 16-byte authentication tag, matching .NET's <see cref="AesGcm"/>
/// convention.
/// </para>
/// <para>
/// <b>Memory hygiene.</b> Plaintext DEK bytes returned by <see cref="IDekManager"/> or
/// <see cref="IKeyEncryptionProvider.UnwrapAsync"/> are zeroed in a <c>finally</c> block after
/// the AES-GCM operation completes, whether it succeeds or throws.
/// </para>
/// <para>
/// <b>Scope binding (M-B).</b> When <see cref="VellumOptions.BindScopeToCiphertext"/> is
/// <see langword="true"/> (the default), <see cref="EncryptAsync"/> produces format version 2
/// envelopes whose AES-GCM associated data binds the ciphertext to its scope — see
/// <see cref="EncryptedPayload.ScopeBoundFormatVersion"/> for the exact AAD layout.
/// <see cref="DecryptAsync"/> reconstructs the same associated data from the caller-supplied
/// scope, so a scope mismatch fails the authentication tag check.
/// </para>
/// </remarks>
public sealed partial class PayloadEncryptor(
    IDekManager dekManager,
    IKeyEncryptionProvider keyProvider,
    IRandomBytesProvider randomBytes,
    IOptions<VellumOptions> options,
    ILogger<PayloadEncryptor> logger) : IPayloadEncryptor
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int DekSizeBytes = 32;

    /// <summary>
    /// Versioned label prefixed to the scope to form the format-version-2 associated data.
    /// The label domain-separates the v2 AAD from any future AAD layout, so a v3 format can
    /// never produce AAD bytes that collide with a v2 envelope's binding.
    /// </summary>
    private const string ScopeAadLabel = "vellum:aad:v2:scope:";

    private readonly IDekManager _dekManager = dekManager ?? throw new ArgumentNullException(nameof(dekManager));
    private readonly IKeyEncryptionProvider _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
    private readonly IRandomBytesProvider _randomBytes = randomBytes ?? throw new ArgumentNullException(nameof(randomBytes));
    private readonly VellumOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
    private readonly ILogger<PayloadEncryptor> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    /// <inheritdoc />
    /// <remarks>
    /// The default implementation is always enabled once the dependencies resolve through DI.
    /// Consumers that want a feature-flagged rollout should wrap this type behind their own
    /// guard, or register an alternative <see cref="IPayloadEncryptor"/> implementation whose
    /// <see cref="IsEnabled"/> is false.
    /// </remarks>
    public bool IsEnabled => true;

    /// <inheritdoc />
    public async Task<EncryptedPayload> EncryptAsync(
        ReadOnlyMemory<byte> plaintext,
        string scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);

        Dek dek = await _dekManager.GetActiveDekAsync(scope, cancellationToken).ConfigureAwait(false);
        try
        {
            // H-1 symmetry (encrypt side): AesGcm accepts 16/24/32-byte keys, so a buggy
            // IDekManager (or KEK provider behind it) returning a short DEK would silently
            // downgrade new envelopes to AES-128. Pin the AES-256 contract here, mirroring
            // the decrypt-side check below, so the downgrade fails closed instead.
            if (dek.Key.Length != DekSizeBytes)
            {
                throw new CryptographicException(
                    $"Active DEK has invalid length: expected {DekSizeBytes} bytes (AES-256), got {dek.Key.Length}.");
            }

            byte[] nonce = new byte[NonceSize];
            _randomBytes.Fill(nonce);

            byte[] ciphertextWithTag = new byte[plaintext.Length + TagSize];
            Span<byte> ciphertextSpan = ciphertextWithTag.AsSpan(0, plaintext.Length);
            Span<byte> tagSpan = ciphertextWithTag.AsSpan(plaintext.Length, TagSize);

            // M-B: bind the ciphertext to its scope via AES-GCM associated data (format
            // version 2) unless the consumer explicitly opted out because the scope is not
            // available at decrypt time. A null byte[] converts to an empty span, which is
            // cryptographically identical to "no AAD" — exactly the version-1 layout.
            bool bindScope = _options.BindScopeToCiphertext;
            byte[]? associatedData = bindScope ? BuildScopeAad(scope) : null;

            using (AesGcm aesGcm = new(dek.Key, TagSize))
            {
                aesGcm.Encrypt(nonce, plaintext.Span, ciphertextSpan, tagSpan, associatedData);
            }

            LogPayloadEncrypted(_logger, scope);
            return new EncryptedPayload(
                ciphertextWithTag,
                nonce,
                dek.WrappedKey,
                dek.KeyId,
                FormatVersion: bindScope
                    ? EncryptedPayload.ScopeBoundFormatVersion
                    : EncryptedPayload.UnboundFormatVersion);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek.Key);
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// Resolves the DEK from <see cref="IEncryptionKeyStore"/> by
    /// <see cref="EncryptedPayload.KeyId"/> first, then falls back to
    /// <see cref="EncryptedPayload.WrappedDek"/>. See the type-level remarks on
    /// <see cref="PayloadEncryptor"/> for why the order is this way round, what the fallback
    /// covers, and what the resulting dependency on the store costs a consumer that has no store.
    /// </para>
    /// <para>
    /// <b>The thrown message carries no backend detail.</b> When both paths fail, the
    /// <see cref="CryptographicException"/> message names only the two failure <i>types</i>. The
    /// original messages — which may contain a host and port, a SQL statement, a Vault URL, or a
    /// wrapped-DEK handle — are available on the inner <see cref="AggregateException"/> and in the
    /// log (EventIds 2001 and 2003), deliberately not in the message, because consumers commonly map
    /// a <see cref="CryptographicException"/> to a client-visible "invalid input" response.
    /// </para>
    /// <para>
    /// <b>What cancellation means here.</b> A store-path failure is handed over to the envelope copy
    /// unless <paramref name="cancellationToken"/> is actually cancelled. The exception type alone is
    /// not the test: a bare <see cref="HttpClient"/> reports a timeout as a
    /// <see cref="TaskCanceledException"/>, and a store that times out is a store failure, not a
    /// cancellation the caller requested.
    /// </para>
    /// <para>
    /// <b>Known consequence of the fallback (B2).</b> The catch around the store path is deliberately
    /// unconditional, so it also absorbs <c>DekManager</c>'s internal cache invariant violation
    /// ("This is a Vellum bug", logged <see cref="LogLevel.Critical"/> under EventId 1003): the
    /// decrypt then succeeds off the envelope copy and the caller sees nothing. Confidentiality is
    /// unaffected — the AES-GCM tag still gates every plaintext — but the <b>only</b> signal for that
    /// invariant is the Critical log entry, not an exception at the call site. Operators must alert on
    /// EventId 1003 rather than expect a failed decrypt.
    /// </para>
    /// </remarks>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "The store-first resolution is an optimisation over a self-contained envelope, not a control: ANY failure of the store path must hand over to the envelope's own wrapped DEK copy, which is exactly what 0.3.x used unconditionally. Narrowing the catch to Vellum's own exception types would leave a consumer whose store is unreachable (DbException, socket failure, ...) worse off than before the reordering, which is the one outcome this change must not produce. A cancellation of the caller's OWN token is re-thrown by the filter — which tests the token rather than the exception type, so that a timeout-shaped TaskCanceledException from an HttpClient still falls back — and the fail-closed guarantee is preserved: when both paths fail the method throws an aggregate naming both failure types.")]
    public async Task<byte[]> DecryptAsync(
        EncryptedPayload payload,
        string scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);

        // The denominator, counted HERE and nowhere else: first statement of the method body, ahead
        // of every validation guard and of both resolution paths, so no exit can miss it — not the
        // four early CryptographicException throws below, not a skipped store lookup, not the
        // aggregate throw when both paths fail, not an OperationCanceledException escaping the
        // filters. One increment per call, before anything can branch, is also the only placement
        // that cannot double-count the decrypts that walk both paths. It deliberately sits AFTER
        // ThrowIfNull: a null payload is a caller contract violation, not a decrypt attempt, and
        // counting it would put a NullReferenceException-class bug into the denominator that the
        // fallback rates are divided by. See VellumDecryptMetrics.DecryptsTotal for why the four
        // fallback gauges cannot be read without this one.
        VellumDecryptMetrics.RecordDecrypt();

        // Fail closed on unknown envelope formats BEFORE any crypto work (no DEK unwrap, no
        // KEK round-trip, no AES-GCM call). A future format may change the AAD, add key
        // commitment, or switch algorithms — interpreting its bytes under a known-version
        // layout would be undefined behavior at best and a security bug at worst.
        if (payload.FormatVersion is not (EncryptedPayload.UnboundFormatVersion or EncryptedPayload.ScopeBoundFormatVersion))
        {
            throw new CryptographicException(
                $"Unsupported envelope format version {payload.FormatVersion}: this version of Vellum only supports format versions {EncryptedPayload.UnboundFormatVersion} and {EncryptedPayload.ScopeBoundFormatVersion}.");
        }

        // M-B: a format version 2 envelope is bound to its scope — refusing a missing scope
        // here (before any unwrap / KEK round-trip) fails closed instead of burning a KEK
        // call on a decrypt that is guaranteed to fail the tag check. Version 1 envelopes
        // carry no binding, so the scope argument is deliberately not validated for them.
        bool scopeBound = payload.FormatVersion == EncryptedPayload.ScopeBoundFormatVersion;
        if (scopeBound && string.IsNullOrEmpty(scope))
        {
            throw new CryptographicException(
                "Scope is required for format version 2 envelopes: the ciphertext is bound to its scope via AES-GCM associated data and cannot be decrypted without it.");
        }

        if (payload.Nonce.Length != NonceSize)
        {
            throw new CryptographicException(
                $"Invalid nonce length: expected {NonceSize} bytes, got {payload.Nonce.Length}.");
        }

        if (payload.Ciphertext.Length < TagSize)
        {
            throw new CryptographicException(
                $"Ciphertext too short to contain a {TagSize}-byte authentication tag.");
        }

        // 0.4.0 — resolution order is store first, envelope copy second.
        //
        // Step 1: ask the store for the DEK behind payload.KeyId. The store holds ONE wrapped-DEK
        // record per key, so re-wrapping a DEK against a different KEK only touches those records;
        // the envelope copies persisted next to every row do not have to be rewritten.
        //
        // The step is skipped when the envelope carries no usable lookup pair: a Guid.Empty KeyId
        // (hand-built envelopes, and the synthetic KeyId DekManager attaches to a wrapped-key
        // resolution) has nothing to look up, and GetDekByKeyIdAsync requires a non-null scope,
        // which format version 1 envelopes are explicitly allowed not to supply (see the scope
        // validation above, deliberately limited to version 2). Skipping is recorded so that these
        // decrypts — which the store can never serve — are visible rather than silently absent
        // from the migration-backlog gauge.
        Exception? storeFailure = null;
        if (payload.KeyId == Guid.Empty || string.IsNullOrEmpty(scope))
        {
            VellumDecryptMetrics.RecordStoreLookupSkipped();
        }
        else
        {
            try
            {
                Dek storeDek = await _dekManager.GetDekByKeyIdAsync(payload.KeyId, scope, cancellationToken).ConfigureAwait(false);
                byte[] plaintext = DecryptWithDek(storeDek, payload, scope, scopeBound);
                LogPayloadDecrypted(_logger, payload.KeyId);
                return plaintext;
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                // Covers BOTH fallback cases with one catch, because both are the same thing from
                // here: (a) the store could not serve the key at all, and (b) it served a record
                // that then failed to unwrap or failed the AES-GCM tag check. Case (b) is the one
                // that makes this reordering safe — a stale store record does not return "nothing",
                // it returns key material that does not work, and without this catch such a payload
                // would stop decrypting even though 0.3.x decrypted it fine off the envelope copy.
                //
                // Note what is NOT inspected: the message. A wrong-mount Vault reply and a missing
                // key are both HTTP 400 and differ only in wording; keying anything on that wording
                // is exactly the fragility this reordering exists to delete.
                //
                // B1: the filter cannot be a bare `ex is not OperationCanceledException`. An
                // HttpClient with no resilience pipeline (VaultOptions.EnableResilience = false)
                // reports a TIMEOUT as a TaskCanceledException, which IS an
                // OperationCanceledException although nobody cancelled anything. Such a store
                // timeout would escape the fallback, uncounted and unlogged, and reach the caller
                // as a cancellation of a token they never cancelled. What identifies a real
                // cancellation is the caller's token, not the exception type — so that is what is
                // tested, and only then is the exception re-thrown.
                storeFailure = ex;
                VellumDecryptMetrics.RecordFallbackAttempt();
                LogStoreLookupFallback(_logger, payload.KeyId, ex);
            }
        }

        // Step 2: the wrapped DEK copy carried by the envelope — the sole path in 0.3.x.
        //
        // Issue #6: route through IDekManager.GetDekByWrappedKeyAsync instead of calling
        // IKeyEncryptionProvider.UnwrapAsync directly. The manager caches unwrapped DEKs
        // keyed by a SHA-256 hash of the wrapped ciphertext so read-heavy workloads avoid
        // a Vault / KMS round-trip on every decrypt. The cache-hit path is synchronous
        // (ValueTask) and allocation-free aside from the required Dek clone. That cache also
        // amortises the doubled KEK traffic a fallback incurs, from the second read onwards.
        try
        {
            Dek dek = await _dekManager.GetDekByWrappedKeyAsync(payload.WrappedDek, cancellationToken).ConfigureAwait(false);
            byte[] plaintext = DecryptWithDek(dek, payload, scope, scopeBound);

            if (storeFailure is not null)
            {
                // A recovered fallback IS the remaining-migration signal: this key's store record
                // is stale and wants rewrapping against the KEK this process can reach.
                VellumDecryptMetrics.RecordFallbackRecovered();
                LogStoreLookupFallbackRecovered(_logger, payload.KeyId);
            }

            LogPayloadDecrypted(_logger, payload.KeyId);
            return plaintext;
        }
        catch (Exception ex) when (storeFailure is not null && (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested))
        {
            // Both paths were tried and both failed: name both in the message. An operator reading
            // a bare "decryption failed" would assume a single path and go looking down the wrong
            // one. The AggregateException inner keeps the two originals intact for a stack trace.
            //
            // M1: the message names the two failure TYPES and nothing else — never the original
            // messages. Since 0.4.0 the store failure can be any infrastructure exception
            // (NpgsqlException with a host:port, SqlException with a server name and SQL text,
            // HttpRequestException with a Vault URL), and this is a CryptographicException, a type
            // many consumers map to "invalid input / 400" and echo straight back to the client. The
            // envelope's WrappedKey.Ciphertext is likewise a wrapped-DEK handle that
            // EncryptedPayload.ToString deliberately refuses to render, so a provider message
            // quoting it must not travel here either. Diagnosis is not lost: both originals are in
            // the inner AggregateException, and the store failure was already logged at EventId 2001
            // with its own exception attached.
            VellumDecryptMetrics.RecordFallbackFailed();
            LogBothDekPathsFailed(_logger, payload.KeyId, ex);
            throw new CryptographicException(
                $"Decryption failed for key {payload.KeyId} after BOTH DEK resolution paths were attempted. "
                + $"(1) Key store lookup by KeyId threw {storeFailure.GetType().FullName}. "
                + $"(2) Fallback to the wrapped DEK carried by the envelope also threw {ex.GetType().FullName}. "
                + "The two original exceptions — including their messages — are preserved in the inner "
                + "AggregateException and in the Vellum log (EventIds 2001 and 2003); they are kept out "
                + "of this message because it may be surfaced to an untrusted caller.",
                new AggregateException(storeFailure, ex));
        }
    }

    /// <summary>
    /// Runs the AES-GCM decryption for an already-resolved <paramref name="dek"/> and takes
    /// ownership of its key bytes: they are zeroed before returning, whether the operation
    /// succeeds or throws. Shared by both resolution paths so the two can never drift apart in
    /// their length check, AAD construction, or memory hygiene.
    /// </summary>
    private static byte[] DecryptWithDek(Dek dek, EncryptedPayload payload, string scope, bool scopeBound)
    {
        try
        {
            // H-1 symmetry: the slow path in DekManager already enforces the AES-256 length
            // contract on unwrap, but pin it again here so that a future refactor of the
            // cache (or a cache-poisoning test asserting the fail-closed behaviour) cannot
            // silently downgrade the cipher strength.
            if (dek.Key.Length != DekSizeBytes)
            {
                throw new CryptographicException(
                    $"Unwrapped DEK has invalid length: expected {DekSizeBytes} bytes (AES-256), got {dek.Key.Length}.");
            }

            int ciphertextLength = payload.Ciphertext.Length - TagSize;
            ReadOnlySpan<byte> ciphertext = payload.Ciphertext.AsSpan(0, ciphertextLength);
            ReadOnlySpan<byte> tag = payload.Ciphertext.AsSpan(ciphertextLength, TagSize);

            byte[] plaintext = new byte[ciphertextLength];

            // M-B: reconstruct the scope AAD for version 2 envelopes. A wrong scope yields
            // different AAD bytes and AES-GCM rejects the authentication tag — that IS the
            // cryptographic scope-binding guarantee, no additional equality check needed.
            byte[]? associatedData = scopeBound ? BuildScopeAad(scope) : null;

            using (AesGcm aesGcm = new(dek.Key, TagSize))
            {
                aesGcm.Decrypt(payload.Nonce, ciphertext, tag, plaintext, associatedData);
            }

            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek.Key);
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// Delegates to <see cref="IKeyEncryptionProvider.RewrapAsync(WrappedKey, CancellationToken)"/>
    /// — the plaintext DEK is never unwrapped here (with a native-rewrap backend such as Vault
    /// Transit, it never leaves the backend at all). Because the DEK plaintext is untouched, the
    /// AES-GCM ciphertext, nonce, key id, and format version are carried over verbatim and the
    /// returned envelope decrypts identically under the same scope.
    /// </remarks>
    public async Task<EncryptedPayload> RewrapPayloadAsync(
        EncryptedPayload payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);

        WrappedKey rewrapped = await _keyProvider.RewrapAsync(payload.WrappedDek, cancellationToken).ConfigureAwait(false);

        LogPayloadRewrapped(_logger, payload.KeyId, rewrapped.ProviderVersion);
        return payload with { WrappedDek = rewrapped };
    }

    /// <summary>
    /// Builds the AES-GCM associated data for a format version 2 envelope:
    /// <c>UTF8("vellum:aad:v2:scope:" + scope)</c>. This is the single place the v2 AAD
    /// layout is defined — encrypt and decrypt both call it, so the two sides can never
    /// drift apart.
    /// </summary>
    private static byte[] BuildScopeAad(string scope) =>
        Encoding.UTF8.GetBytes(ScopeAadLabel + scope);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Payload encrypted for scope {Scope}")]
    private static partial void LogPayloadEncrypted(ILogger logger, string scope);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Payload decrypted with key {KeyId}")]
    private static partial void LogPayloadDecrypted(ILogger logger, Guid keyId);

    // 0.4.0 — EventIds 2001/2002/2003 are stable and distinct so an operator can alert on the
    // three outcomes separately: a fallback was needed (2001), it worked and therefore names a
    // key record still to migrate (2002), or both resolution paths failed (2003).

    [LoggerMessage(
        EventId = 2001,
        Level = LogLevel.Warning,
        Message = "Key store lookup for DEK {KeyId} failed; falling back to the wrapped DEK carried by the envelope")]
    private static partial void LogStoreLookupFallback(ILogger logger, Guid keyId, Exception exception);

    [LoggerMessage(
        EventId = 2002,
        Level = LogLevel.Warning,
        Message = "Decrypt recovered via the envelope's own wrapped DEK after the key store lookup for {KeyId} failed: the stored key record is stale and should be rewrapped against the reachable KEK")]
    private static partial void LogStoreLookupFallbackRecovered(ILogger logger, Guid keyId);

    [LoggerMessage(
        EventId = 2003,
        Level = LogLevel.Error,
        Message = "Decrypt failed for DEK {KeyId} after BOTH the key store lookup and the envelope's wrapped DEK copy were tried")]
    private static partial void LogBothDekPathsFailed(ILogger logger, Guid keyId, Exception exception);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Payload envelope rewrapped for key {KeyId} (new provider version {ProviderVersion})")]
    private static partial void LogPayloadRewrapped(ILogger logger, Guid keyId, string providerVersion);
}
