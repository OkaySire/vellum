using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Vellum;
using Vellum.InMemory;
using Vellum.Static;

// ---------------------------------------------------------------------------
// Vellum — minimal console sample (Static KEK + InMemory store).
//
// The 20-line Hello World for Vellum. Encrypts a string, decrypts it, prints
// both sides. Uses Vellum.Static (dev-only!) so the sample has no external
// dependencies — no Vault, no KMS, no database.
//
// ⚠️ Vellum.Static is INSECURE: it stores the Key Encryption Key in process
// memory, initialised from config. Use it for local tinkering and tests only.
// In production, use Vellum.Vault / Vellum.AzureKeyVault / Vellum.AwsKms /
// Vellum.GcpKms.
//
// Run: dotnet run --project samples/Console.Static
// ---------------------------------------------------------------------------

// Generate a one-shot dev KEK (never ship anything like this).
byte[] devKekBytes = new byte[32];
RandomNumberGenerator.Fill(devKekBytes);

ServiceCollection services = new();
services.AddLogging();
services.AddVellum();
services.AddStaticProvider(opts => opts.Base64Key = Convert.ToBase64String(devKekBytes));
services.AddInMemoryStore();

await using ServiceProvider provider = services.BuildServiceProvider();

IPayloadEncryptor encryptor = provider.GetRequiredService<IPayloadEncryptor>();

EncryptedPayload envelope = await encryptor.EncryptStringAsync(
    "hello from Vellum.Static",
    scope: "tenant:demo");

Console.WriteLine($"KeyId:            {envelope.KeyId}");
Console.WriteLine($"Ciphertext bytes: {envelope.Ciphertext.Length} (plaintext + 16-byte auth tag)");
Console.WriteLine($"Nonce bytes:      {envelope.Nonce.Length}");
Console.WriteLine($"Wrapped provider: {envelope.WrappedDek.ProviderVersion}");
Console.WriteLine();

string roundtrip = await encryptor.DecryptStringAsync(envelope, scope: "tenant:demo");
Console.WriteLine($"Decrypted:        \"{roundtrip}\"");
