using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum.Tests.Fakes;
using Xunit;

namespace Vellum.Tests;

public sealed class PayloadEncryptorTests
{
    private const string Scope = "tenant:42";

    private static (PayloadEncryptor Encryptor, FakeKeyEncryptionProvider Provider, DekManager DekManager)
        BuildSut()
    {
        FakeKeyEncryptionProvider provider = new();
        FakeEncryptionKeyStore store = new();
        CountingRandomBytesProvider random = new();
        MemoryCache cache = new(new MemoryCacheOptions());
        VellumOptions options = new();

        DekManager dekManager = new(
            provider,
            store,
            cache,
            random,
            TimeProvider.System,
            Options.Create(options),
            NullLogger<DekManager>.Instance);

        PayloadEncryptor encryptor = new(
            dekManager,
            provider,
            random,
            NullLogger<PayloadEncryptor>.Instance);

        return (encryptor, provider, dekManager);
    }

    [Fact]
    public void IsEnabled_Default_IsTrue()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();
        encryptor.IsEnabled.Should().BeTrue();
    }

    [Fact]
    public async Task EncryptDecrypt_Roundtrip_BinaryPayload()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("hello vellum — \u0041\u00e9");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);
        byte[] decrypted = await encryptor.DecryptAsync(envelope);

        decrypted.Should().Equal(plaintext);
        envelope.Nonce.Should().HaveCount(12);
        envelope.Ciphertext.Length.Should().Be(plaintext.Length + 16);
    }

    [Fact]
    public async Task EncryptDecrypt_Roundtrip_EmptyPayload()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Array.Empty<byte>();
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);
        byte[] decrypted = await encryptor.DecryptAsync(envelope);

        decrypted.Should().BeEmpty();
        envelope.Ciphertext.Length.Should().Be(16, "empty plaintext still carries a 16-byte auth tag");
    }

    [Fact]
    public async Task EncryptTwice_SamePlaintext_ProducesDifferentCiphertexts()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("repeated plaintext");
        EncryptedPayload first = await encryptor.EncryptAsync(plaintext, Scope);
        EncryptedPayload second = await encryptor.EncryptAsync(plaintext, Scope);

        first.Nonce.Should().NotEqual(second.Nonce, "nonces must never repeat");
        first.Ciphertext.Should().NotEqual(second.Ciphertext);
    }

    [Fact]
    public async Task Decrypt_TamperedCiphertext_Throws()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("tamper me");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        envelope.Ciphertext[0] ^= 0xFF;

        Func<Task> act = async () => await encryptor.DecryptAsync(envelope);
        await act.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task Decrypt_TamperedNonce_Throws()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("swap the nonce");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        envelope.Nonce[0] ^= 0xFF;

        Func<Task> act = async () => await encryptor.DecryptAsync(envelope);
        await act.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task Decrypt_NonceOfWrongLength_Throws()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("short nonce");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);
        EncryptedPayload malformed = new(envelope.Ciphertext, new byte[8], envelope.WrappedDek, envelope.KeyId);

        Func<Task> act = async () => await encryptor.DecryptAsync(malformed);
        await act.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task Decrypt_CiphertextShorterThanTag_Throws()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("tag check");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);
        EncryptedPayload malformed = new(new byte[8], envelope.Nonce, envelope.WrappedDek, envelope.KeyId);

        Func<Task> act = async () => await encryptor.DecryptAsync(malformed);
        await act.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task Decrypt_SelfContained_DoesNotCallDekManager()
    {
        // The envelope embeds its own WrappedKey, so decryption must go through the KEK
        // provider only — never back to IDekManager / IEncryptionKeyStore. This pins the
        // self-contained envelope contract (C3).
        (PayloadEncryptor encryptor, FakeKeyEncryptionProvider provider, _) = BuildSut();

        byte[] plaintext = Encoding.UTF8.GetBytes("self contained");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        int unwrapsBefore = provider.UnwrapCalls;
        _ = await encryptor.DecryptAsync(envelope);
        provider.UnwrapCalls.Should().Be(unwrapsBefore + 1, "decrypt goes straight through the KEK provider");
    }

    [Fact]
    public async Task StringConvenience_Roundtrip()
    {
        (PayloadEncryptor encryptor, _, _) = BuildSut();

        EncryptedPayload envelope = await encryptor.EncryptStringAsync("Hé, Vellum!", Scope);
        string decrypted = await encryptor.DecryptStringAsync(envelope);

        decrypted.Should().Be("Hé, Vellum!");
    }

    [Fact]
    public async Task Decrypt_ProviderReturnsShortDek_ThrowsAndPreservesAes256Contract()
    {
        // H-1: pin the fail-closed behavior on the unwrap path. A buggy or compromised KEK
        // provider returning a 16-byte DEK must NOT silently downgrade the envelope to
        // AES-128. PayloadEncryptor must reject the unwrapped key and throw before calling
        // AesGcm.Decrypt.
        FakeKeyEncryptionProvider realProvider = new();
        FakeEncryptionKeyStore store = new();
        CountingRandomBytesProvider random = new();
        MemoryCache cache = new(new MemoryCacheOptions());
        VellumOptions options = new();

        DekManager dekManager = new(
            realProvider,
            store,
            cache,
            random,
            TimeProvider.System,
            Options.Create(options),
            NullLogger<DekManager>.Instance);

        PayloadEncryptor encryptor = new(
            dekManager,
            realProvider,
            random,
            NullLogger<PayloadEncryptor>.Instance);

        byte[] plaintext = Encoding.UTF8.GetBytes("downgrade check");
        EncryptedPayload envelope = await encryptor.EncryptAsync(plaintext, Scope);

        // Now build a decrypt-side encryptor whose KEK provider returns 16 bytes instead
        // of 32. Re-use the envelope minted above so everything else is legitimate.
        ShortDekKeyEncryptionProvider shortProvider = new(dekBytesLength: 16);
        PayloadEncryptor decryptOnly = new(
            dekManager,
            shortProvider,
            random,
            NullLogger<PayloadEncryptor>.Instance);

        Func<Task> act = async () => await decryptOnly.DecryptAsync(envelope);
        await act.Should().ThrowAsync<CryptographicException>()
            .WithMessage("*expected 32 bytes*");
    }

    /// <summary>
    /// Minimal KEK provider whose <see cref="UnwrapAsync"/> returns a buffer of the
    /// configured length, regardless of what was wrapped. Used to prove that Vellum
    /// rejects short/long DEKs on the decrypt path.
    /// </summary>
    private sealed class ShortDekKeyEncryptionProvider(int dekBytesLength) : IKeyEncryptionProvider
    {
        public string ProviderName => "short-fake";

        public Task<WrappedKey> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken cancellationToken = default)
            => Task.FromResult(new WrappedKey("short:v1", "v1"));

        public Task<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
            => Task.FromResult(new byte[dekBytesLength]);
    }
}
