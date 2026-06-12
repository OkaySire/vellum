using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum;
using Vellum.InMemory;
using Vellum.Samples.FeatureFlagged;
using Vellum.Static;

// ---------------------------------------------------------------------------
// Vellum feature-flagged encryption sample.
//
// Shows a minimal IPayloadEncryptor decorator that gates envelope encryption on
// a consumer-owned feature flag (FeatureFlags.EncryptionEnabled). When the flag
// is off, Encrypt returns a sentinel envelope that Decrypt recognises and
// short-circuits to plaintext passthrough — so a staged rollout can flip
// encryption on and off without touching DI or rewriting call sites.
//
// Run: dotnet run --project samples/FeatureFlagged
//
// The sample deliberately constructs the encryptor by hand (no DI container) to
// keep the focus on the decorator itself. For a real app, register the decorator
// via Scrutor's services.Decorate<IPayloadEncryptor, FeatureFlaggedPayloadEncryptor>()
// or an equivalent manual ServiceDescriptor replacement.
// ---------------------------------------------------------------------------

Console.WriteLine("Vellum feature-flagged encryption sample");
Console.WriteLine("========================================");
Console.WriteLine();

// Scenario 1: flag ON — real envelope.
IPayloadEncryptor encryptorOn = BuildEncryptor(encryptionEnabled: true);
await RoundtripAsync(encryptorOn, "hello from flag-ON", scenario: "ON");
Console.WriteLine();

// Scenario 2: flag OFF — sentinel passthrough envelope.
IPayloadEncryptor encryptorOff = BuildEncryptor(encryptionEnabled: false);
await RoundtripAsync(encryptorOff, "hello from flag-OFF", scenario: "OFF");
Console.WriteLine();

Console.WriteLine("Sample completed.");

// ---------------------------------------------------------------------------
// Helpers — construct a minimal Vellum stack wrapped by the feature-flag decorator.
// ---------------------------------------------------------------------------
static IPayloadEncryptor BuildEncryptor(bool encryptionEnabled)
{
    IRandomBytesProvider rng = new DefaultRandomBytesProvider();

    // ⚠️ StaticKeyEncryptionProvider is DEV-ONLY — never ship a KEK that lives in config.
    byte[] devKekBytes = new byte[32];
    System.Security.Cryptography.RandomNumberGenerator.Fill(devKekBytes);
    StaticOptions staticOptions = new() { Base64Key = Convert.ToBase64String(devKekBytes) };
    IKeyEncryptionProvider kek = new StaticKeyEncryptionProvider(
        Options.Create(staticOptions),
        NullLogger<StaticKeyEncryptionProvider>.Instance);

    IEncryptionKeyStore store = new InMemoryEncryptionKeyStore(
        NullLogger<InMemoryEncryptionKeyStore>.Instance);

    // Vellum-owned DEK cache (M-C): never the application's shared IMemoryCache.
    VellumDekCache cache = new();

    IDekManager dekManager = new DekManager(
        kek,
        store,
        cache,
        rng,
        TimeProvider.System,
        Options.Create(new VellumOptions()),
        NullLogger<DekManager>.Instance);

    IPayloadEncryptor inner = new PayloadEncryptor(
        dekManager,
        kek,
        rng,
        Options.Create(new VellumOptions()),
        NullLogger<PayloadEncryptor>.Instance);

    // Wrap with the feature-flag decorator. The real pattern uses IOptionsMonitor so the
    // flag can hot-reload mid-process; here we use a fixed snapshot for simplicity.
    FeatureFlags flags = new() { EncryptionEnabled = encryptionEnabled };
    IOptionsMonitor<FeatureFlags> monitor = new StaticOptionsMonitor<FeatureFlags>(flags);
    return new FeatureFlaggedPayloadEncryptor(inner, monitor);
}

static async Task RoundtripAsync(IPayloadEncryptor encryptor, string text, string scenario)
{
    byte[] plaintext = Encoding.UTF8.GetBytes(text);
    EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, scope: "tenant:alpha");
    Console.WriteLine(
        $"[{scenario}] ciphertext-length={envelope.Ciphertext.Length}, " +
        $"nonce-length={envelope.Nonce.Length}, " +
        $"provider={envelope.WrappedDek.ProviderVersion}");

    byte[] roundtrip = await encryptor.DecryptAsync(envelope, scope: "tenant:alpha");
    Console.WriteLine($"[{scenario}] decrypted: \"{Encoding.UTF8.GetString(roundtrip)}\"");
}
