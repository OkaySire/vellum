using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Vellum;
using Vellum.InMemory;
using Vellum.Static;

// ---------------------------------------------------------------------------
// Vellum — DEK rotation, scope binding and KEK rewrap walkthrough.
//
// A narrated console tour of the 0.2.0 key-lifecycle features, with zero
// external infrastructure (Static KEK + InMemory store — see Console.Static
// for the warnings about Vellum.Static; same rules apply here):
//
//   1. Encrypt under two scopes — each scope gets its own DEK.
//   2. Manual DEK rotation (IDekManager.RotateDekAsync): new encrypts use the
//      new DEK; historical envelopes stay decryptable (self-contained).
//   3. Cross-scope binding: a v2 envelope presented under the wrong scope
//      fails the AES-GCM authentication tag check (fail closed).
//   4. KEK rewrap (VellumRewrapService + RewrapPayloadAsync): refresh the
//      wrapped DEKs without touching the payload bytes — steps 2 and 3 of the
//      docs/kek-rotation.md runbook.
//   5. Opt-out: BindScopeToCiphertext = false produces legacy v1 envelopes.
//
// Run: dotnet run --project samples/RotationAndRewrap
// ---------------------------------------------------------------------------

// Generate a one-shot dev KEK (never ship anything like this).
byte[] devKekBytes = new byte[32];
RandomNumberGenerator.Fill(devKekBytes);

WriteSection("1. Setup — AddVellum + Static KEK + InMemory store, two scopes");

ServiceCollection services = new();
services.AddLogging();
services.AddVellum();
services.AddStaticProvider(opts => opts.Base64Key = Convert.ToBase64String(devKekBytes));
services.AddInMemoryStore();

await using ServiceProvider provider = services.BuildServiceProvider();

IPayloadEncryptor encryptor = provider.GetRequiredService<IPayloadEncryptor>();
IDekManager dekManager = provider.GetRequiredService<IDekManager>();
VellumRewrapService rewrapService = provider.GetRequiredService<VellumRewrapService>();

Console.WriteLine("Scopes in play: \"tenant:alpha\" and \"tenant:beta\".");

WriteSection("2. Encrypt — each scope gets its own DEK, envelopes are v2 (scope-bound)");

EncryptedPayload alphaFirst = await encryptor.EncryptStringAsync("alpha secret #1", scope: "tenant:alpha");
Console.WriteLine($"tenant:alpha KeyId: {alphaFirst.KeyId}");
Console.WriteLine($"FormatVersion:      {alphaFirst.FormatVersion} (v2: the scope is baked into the AES-GCM associated data)");

EncryptedPayload betaEnvelope = await encryptor.EncryptStringAsync("beta secret", scope: "tenant:beta");
Console.WriteLine($"tenant:beta KeyId:  {betaEnvelope.KeyId} (different scope, different DEK)");

WriteSection("3. Manual rotation — IDekManager.RotateDekAsync(\"tenant:alpha\")");

await dekManager.RotateDekAsync("tenant:alpha");

EncryptedPayload alphaSecond = await encryptor.EncryptStringAsync("alpha secret #2", scope: "tenant:alpha");
Console.WriteLine($"KeyId before rotation: {alphaFirst.KeyId}");
Console.WriteLine($"KeyId after rotation:  {alphaSecond.KeyId}");
Console.WriteLine($"KeyId changed:         {alphaFirst.KeyId != alphaSecond.KeyId}");

// The first envelope embeds its own wrapped DEK, so rotation never strands it:
// decryption unwraps the historical DEK straight off the envelope.
string firstRoundtrip = await encryptor.DecryptStringAsync(alphaFirst, scope: "tenant:alpha");
Console.WriteLine($"Pre-rotation envelope still decrypts: \"{firstRoundtrip}\"");

WriteSection("4. Cross-scope binding — tenant:alpha's envelope presented as tenant:beta's");

try
{
    _ = await encryptor.DecryptStringAsync(alphaFirst, scope: "tenant:beta");
    Console.WriteLine("UNEXPECTED: cross-scope decrypt succeeded — this must never happen.");
}
catch (CryptographicException ex)
{
    Console.WriteLine($"Rejected with {ex.GetType().Name}:");
    Console.WriteLine("the AAD scope binding failed the AES-GCM authentication tag check (fail closed).");
}

WriteSection("5. KEK rewrap — refresh wrapped DEKs without touching payload bytes");

// Step 2 of the docs/kek-rotation.md runbook: rewrap the scope's STORED keys
// (active + historical) under the KEK provider's current key version.
// With the Static dev provider, rewrap is an in-process unwrap + wrap; with
// Vellum.Vault it delegates to Transit's /rewrap endpoint, so the plaintext
// DEKs never leave Vault.
RewrapScopeResult sweep = await rewrapService.RewrapStoredKeysAsync("tenant:alpha");
Console.WriteLine($"Stored-key sweep:  Total={sweep.Total}, Rewrapped={sweep.Rewrapped}, Failed={sweep.Failed}");

// Step 3 of the runbook: every persisted envelope embeds its own copy of the
// wrapped DEK, so each one needs RewrapPayloadAsync too.
EncryptedPayload rewrapped = await encryptor.RewrapPayloadAsync(alphaFirst);
Console.WriteLine($"WrappedDek before:    {Truncate(alphaFirst.WrappedDek.Ciphertext)}");
Console.WriteLine($"WrappedDek after:     {Truncate(rewrapped.WrappedDek.Ciphertext)}");
Console.WriteLine($"WrappedDek changed:   {alphaFirst.WrappedDek.Ciphertext != rewrapped.WrappedDek.Ciphertext}");
Console.WriteLine($"Ciphertext identical: {rewrapped.Ciphertext.AsSpan().SequenceEqual(alphaFirst.Ciphertext)}");
Console.WriteLine($"Nonce identical:      {rewrapped.Nonce.AsSpan().SequenceEqual(alphaFirst.Nonce)}");
Console.WriteLine($"KeyId identical:      {rewrapped.KeyId == alphaFirst.KeyId}");
Console.WriteLine($"FormatVersion same:   {rewrapped.FormatVersion == alphaFirst.FormatVersion}");

string rewrappedRoundtrip = await encryptor.DecryptStringAsync(rewrapped, scope: "tenant:alpha");
Console.WriteLine($"Rewrapped envelope round-trips: \"{rewrappedRoundtrip}\"");

WriteSection("6. Opt-out — BindScopeToCiphertext = false produces legacy v1 envelopes");

ServiceCollection unboundServices = new();
unboundServices.AddLogging();
unboundServices.AddVellum(opts => opts.BindScopeToCiphertext = false);
unboundServices.AddStaticProvider(opts => opts.Base64Key = Convert.ToBase64String(devKekBytes));
unboundServices.AddInMemoryStore();

await using ServiceProvider unboundProvider = unboundServices.BuildServiceProvider();
IPayloadEncryptor unboundEncryptor = unboundProvider.GetRequiredService<IPayloadEncryptor>();

EncryptedPayload v1Envelope = await unboundEncryptor.EncryptStringAsync("legacy-style envelope", scope: "tenant:alpha");
Console.WriteLine($"FormatVersion: {v1Envelope.FormatVersion} (v1: no AAD)");

string v1Roundtrip = await unboundEncryptor.DecryptStringAsync(v1Envelope, scope: "tenant:beta");
Console.WriteLine($"Decrypts under ANY scope argument — here \"tenant:beta\": \"{v1Roundtrip}\"");
Console.WriteLine("Only opt out when the scope genuinely cannot be supplied at decrypt time.");

Console.WriteLine();
Console.WriteLine("Done. Full KEK-rotation procedure: docs/kek-rotation.md");

static void WriteSection(string title)
{
    Console.WriteLine();
    Console.WriteLine($"=== {title} ===");
}

static string Truncate(string value) =>
    value.Length <= 28 ? value : $"{value[..28]}... ({value.Length} chars)";
