using System.Reflection;

using FluentAssertions;

using Xunit;

namespace Vellum.Tests;

/// <summary>
/// Phase 1.2 smoke tests for <c>Vellum.Abstractions</c>.
/// </summary>
/// <remarks>
/// These tests intentionally cover the bare-minimum contracts requested by the
/// Phase 1.1/1.2 review (M8): value-equality semantics of the envelope and key records,
/// cloning-semantics of <see cref="Dek"/>, <see cref="WrappedKey"/> construction, and
/// cross-TFM assembly loadability.
/// </remarks>
public sealed class AbstractionsSmokeTests
{
    [Fact]
    public void EncryptionKey_ValueEquality_ByAllFields()
    {
        Guid keyId = Guid.NewGuid();
        WrappedKey wrapped = new("vault:v1:abc", "1");
        DateTimeOffset createdAt = new(2026, 4, 9, 0, 0, 0, TimeSpan.Zero);

        EncryptionKey a = new(keyId, "tenant:42", wrapped, createdAt, null, true);
        EncryptionKey b = new(keyId, "tenant:42", wrapped, createdAt, null, true);
        EncryptionKey differentScope = a with { Scope = "tenant:43" };

        a.Should().Be(b);
        a.GetHashCode().Should().Be(b.GetHashCode());
        a.Should().NotBe(differentScope);
    }

    [Fact]
    public void EncryptedPayload_ValueEquality_StructuralOverByteArrays()
    {
        // Two DIFFERENT byte[] instances with the same content must compare equal.
        // The record's compiler-generated equality would compare byte[] by reference
        // and return false, so EncryptedPayload overrides Equals/GetHashCode to use
        // SequenceEqual. This test pins that contract.
        byte[] ciphertextA = [1, 2, 3, 4, 5];
        byte[] ciphertextB = [1, 2, 3, 4, 5];
        byte[] nonceA = new byte[12];
        byte[] nonceB = new byte[12];
        Guid keyId = Guid.NewGuid();
        WrappedKey wrapped = new("vault:v1:abc", "1");

        EncryptedPayload a = new(ciphertextA, nonceA, wrapped, keyId);
        EncryptedPayload b = new(ciphertextB, nonceB, wrapped, keyId);

        a.Should().Be(b);
        a.GetHashCode().Should().Be(b.GetHashCode());

        byte[] ciphertextDifferent = [1, 2, 3, 4, 6];
        EncryptedPayload c = new(ciphertextDifferent, nonceA, wrapped, keyId);

        a.Should().NotBe(c);
    }

    [Fact]
    public void Dek_Key_IsStoredByReference_SoCachesMustClone()
    {
        // This test pins the documented contract from tasks/lessons.md L3:
        // Dek stores the byte[] by reference, NOT by copy. A caller that mutates
        // (or zeros) the underlying array will see the Dek.Key reflect the mutation.
        // This is WHY cache implementations must clone before returning.
        byte[] keyBytes = new byte[32];
        for (int i = 0; i < keyBytes.Length; i++)
        {
            keyBytes[i] = (byte)i;
        }

        WrappedKey wrapped = new("vault:v1:abc", "1");
        Dek dek = new(keyBytes, Guid.NewGuid(), wrapped);
        ReferenceEquals(dek.Key, keyBytes).Should().BeTrue("Dek must store the array by reference");

        // Mutate the original array and verify the Dek reflects the change.
        keyBytes[0] = 0xFF;
        dek.Key[0].Should().Be(0xFF, "proving Dek does not defensively copy \u2014 cache impls must clone");
    }

    [Fact]
    public void WrappedKey_Construction_RoundTripsFields()
    {
        // N8: ProviderVersion is now an opaque string so we can carry AWS ARNs,
        // Azure KV URIs, GCP resource paths, or Vault integer strings interchangeably.
        WrappedKey vault = new("vault:v1:ZmFrZQ==", "1");
        WrappedKey aws = new("AQICAHjk...", "arn:aws:kms:us-east-1:111122223333:key/abc-def");
        WrappedKey azure = new("base64blob", "https://kv.vault.azure.net/keys/my-key/0123456789abcdef0123456789abcdef");

        vault.Ciphertext.Should().Be("vault:v1:ZmFrZQ==");
        vault.ProviderVersion.Should().Be("1");
        aws.ProviderVersion.Should().StartWith("arn:aws:kms:");
        azure.ProviderVersion.Should().Contain("vault.azure.net");

        // Record value equality.
        WrappedKey vaultDuplicate = new("vault:v1:ZmFrZQ==", "1");
        vault.Should().Be(vaultDuplicate);
    }

    [Fact]
    public void VellumAbstractionsAssembly_LoadsOnCurrentTargetFramework()
    {
        // The test project multi-targets net8.0;net9.0;net10.0 (via Directory.Build.props).
        // Running this test on each TFM proves the assembly loads and the public types
        // are reachable on that runtime.
        Assembly assembly = typeof(IPayloadEncryptor).Assembly;
        assembly.GetName().Name.Should().Be("Vellum.Abstractions");

        Type[] expectedTypes =
        [
            typeof(IKeyEncryptionProvider),
            typeof(IEncryptionKeyStore),
            typeof(IDekManager),
            typeof(IPayloadEncryptor),
            typeof(IRandomBytesProvider),
            typeof(EncryptionKey),
            typeof(EncryptedPayload),
            typeof(Dek),
            typeof(WrappedKey),
            typeof(PayloadEncryptorExtensions),
        ];

        foreach (Type expected in expectedTypes)
        {
            assembly.GetType(expected.FullName!).Should().NotBeNull(
                "{0} should be present on {1}",
                expected.FullName,
                System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
        }
    }

    [Fact]
    public void EncryptedPayload_ToString_HidesCiphertextAndWrappedKey()
    {
        // M-1: pin the safe ToString override. The compiler-generated record ToString
        // would print Ciphertext, Nonce, and WrappedDek verbatim. The override returns a
        // fixed summary with lengths only.
        byte[] ciphertext = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        byte[] nonce = [0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44];
        string sensitiveCiphertext = "vault:v1:SENSITIVE-DO-NOT-LOG";
        WrappedKey wrapped = new(sensitiveCiphertext, "v1");
        EncryptedPayload envelope = new(ciphertext, nonce, wrapped, Guid.NewGuid());

        string printed = envelope.ToString();

        printed.Should().NotContain(sensitiveCiphertext, "the wrapped ciphertext must never appear in ToString output");
        printed.Should().Contain($"KeyId = {envelope.KeyId}");
        printed.Should().Contain($"CiphertextLength = {ciphertext.Length}");
        printed.Should().Contain($"NonceLength = {nonce.Length}");
    }

    [Fact]
    public void Dek_ToString_HidesKeyBytes()
    {
        // M-2: pin the safe ToString override. Must never expose hex or base64 of the
        // key bytes, only a fixed KeyId + KeyLength summary.
        //
        // We use a deterministic key pattern (00,01,02,...,1F) and check for the EXACT
        // hex/base64 string representation of the buffer rather than searching for
        // individual byte substrings. Looking for a 2-char hex substring is statistically
        // useless (1 in 16 collision per position in the GUID alone) and historically
        // produced a flaky test that collided with hex characters inside the KeyId guid.
        byte[] key = new byte[32];
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = (byte)i;
        }

        Dek dek = new(key, Guid.NewGuid(), new WrappedKey("vault:v1:abc", "v1"));

        string printed = dek.ToString();

        printed.Should().Contain($"KeyId = {dek.KeyId}");
        printed.Should().Contain("KeyLength = 32");

        // The deterministic full hex/base64 of the buffer must NOT appear anywhere.
        string hexRepresentation = Convert.ToHexString(key);
        string base64Representation = Convert.ToBase64String(key);
        printed.Should().NotContain(hexRepresentation,
            "full hex representation of key bytes must not leak");
        printed.Should().NotContain(base64Representation,
            "full base64 representation of key bytes must not leak");

        // And the type-name fallback must not appear either (the compiler-generated
        // output prints "Key = System.Byte[]").
        printed.Should().NotContain("System.Byte");

        // Belt-and-braces: ToString() must be a fixed-size summary, bounded well below
        // the size of any reasonable buffer echo. 128 chars is comfortably above the
        // expected "Dek { KeyId = <guid>, KeyLength = 32 }" (~60 chars) and well below
        // the size of a hex-dumped 32-byte key (~64 chars plus formatting noise).
        printed.Length.Should().BeLessThan(128,
            "ToString must be a fixed-size summary, not contain the key buffer");
    }
}
