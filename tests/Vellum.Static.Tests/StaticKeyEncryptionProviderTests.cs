using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum.Static.Tests.Fakes;
using Xunit;

namespace Vellum.Static.Tests;

public sealed class StaticKeyEncryptionProviderTests
{
    private static readonly byte[] _kek32 =
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];

    private static readonly byte[] _alternateKek32 =
    [
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
        0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0,
    ];

    private static StaticKeyEncryptionProvider CreateProvider(
        byte[]? kek = null,
        ILogger<StaticKeyEncryptionProvider>? logger = null)
    {
        StaticOptions options = new()
        {
            Base64Key = Convert.ToBase64String(kek ?? _kek32),
        };
        return new StaticKeyEncryptionProvider(
            Options.Create(options),
            logger ?? NullLogger<StaticKeyEncryptionProvider>.Instance);
    }

    [Fact]
    public void ProviderName_IsStatic()
    {
        StaticKeyEncryptionProvider provider = CreateProvider();

        provider.ProviderName.Should().Be("static");
    }

    [Fact]
    public async Task WrapThenUnwrap_Roundtrip_ReturnsOriginalDek()
    {
        StaticKeyEncryptionProvider provider = CreateProvider();
        byte[] dek = RandomNumberGenerator.GetBytes(32);

        WrappedKey wrapped = await provider.WrapAsync(dek);
        byte[] unwrapped = await provider.UnwrapAsync(wrapped);

        unwrapped.Should().Equal(dek);
        wrapped.ProviderVersion.Should().Be("v1");
        wrapped.Ciphertext.Should().StartWith("static:v1:");
    }

    [Fact]
    public async Task WrapAsync_ProducesDifferentCiphertexts_ForSameDek()
    {
        StaticKeyEncryptionProvider provider = CreateProvider();
        byte[] dek = RandomNumberGenerator.GetBytes(32);

        WrappedKey first = await provider.WrapAsync(dek);
        WrappedKey second = await provider.WrapAsync(dek);

        // Identical ciphertexts would mean nonce reuse — catastrophic for AES-GCM.
        first.Ciphertext.Should().NotBe(second.Ciphertext);

        // Both should still unwrap back to the original DEK.
        (await provider.UnwrapAsync(first)).Should().Equal(dek);
        (await provider.UnwrapAsync(second)).Should().Equal(dek);
    }

    [Fact]
    public async Task UnwrapAsync_TamperedCiphertext_ThrowsCryptographicException()
    {
        StaticKeyEncryptionProvider provider = CreateProvider();
        byte[] dek = RandomNumberGenerator.GetBytes(32);

        WrappedKey wrapped = await provider.WrapAsync(dek);

        // Flip one byte inside the base64 blob to corrupt the authentication tag.
        string body = wrapped.Ciphertext["static:v1:".Length..];
        byte[] blob = Convert.FromBase64String(body);
        blob[^1] ^= 0x01;
        WrappedKey tampered = new("static:v1:" + Convert.ToBase64String(blob), "v1");

        Func<Task> act = async () => await provider.UnwrapAsync(tampered);

        await act.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task UnwrapAsync_WrongKek_ThrowsCryptographicException()
    {
        StaticKeyEncryptionProvider writer = CreateProvider(_kek32);
        StaticKeyEncryptionProvider reader = CreateProvider(_alternateKek32);
        byte[] dek = RandomNumberGenerator.GetBytes(32);

        WrappedKey wrapped = await writer.WrapAsync(dek);

        Func<Task> act = async () => await reader.UnwrapAsync(wrapped);

        await act.Should().ThrowAsync<CryptographicException>();
    }

    [Fact]
    public async Task UnwrapAsync_InvalidPrefix_ThrowsInvalidOperationException()
    {
        StaticKeyEncryptionProvider provider = CreateProvider();
        WrappedKey wrongPrefix = new("vault:v1:AAAA", "v1");

        Func<Task> act = async () => await provider.UnwrapAsync(wrongPrefix);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*does not start with 'static:v1:'*");
    }

    [Fact]
    public async Task UnwrapAsync_InvalidBase64_ThrowsInvalidOperationException()
    {
        StaticKeyEncryptionProvider provider = CreateProvider();
        WrappedKey malformed = new("static:v1:!!!not-base64!!!", "v1");

        Func<Task> act = async () => await provider.UnwrapAsync(malformed);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*not valid base64*");
    }

    [Fact]
    public async Task UnwrapAsync_TooShortBlob_ThrowsInvalidOperationException()
    {
        StaticKeyEncryptionProvider provider = CreateProvider();
        // 16 bytes of junk — smaller than nonce(12) + tag(16) = 28.
        WrappedKey tooShort = new(
            "static:v1:" + Convert.ToBase64String(new byte[16]),
            "v1");

        Func<Task> act = async () => await provider.UnwrapAsync(tooShort);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*too short*");
    }

    [Fact]
    public async Task UnwrapAsync_NullWrappedKey_Throws()
    {
        StaticKeyEncryptionProvider provider = CreateProvider();

        Func<Task> act = async () => await provider.UnwrapAsync(null!);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task WrapAsync_EmptyDek_Throws()
    {
        StaticKeyEncryptionProvider provider = CreateProvider();

        Func<Task> act = async () => await provider.WrapAsync(ReadOnlyMemory<byte>.Empty);

        await act.Should().ThrowAsync<ArgumentException>()
            .Where(ex => ex.ParamName == "dek");
    }

    [Fact]
    public async Task StartupWarning_IsLogged_OnFirstWrap()
    {
        CapturingLogger<StaticKeyEncryptionProvider> logger = new();
        StaticKeyEncryptionProvider provider = CreateProvider(logger: logger);

        byte[] dek = RandomNumberGenerator.GetBytes(32);
        _ = await provider.WrapAsync(dek);

        logger.Entries.Should().ContainSingle(entry =>
            entry.Level == LogLevel.Warning &&
            entry.Message.Contains("DEVELOPMENT USE ONLY", StringComparison.Ordinal));
    }

    [Fact]
    public async Task StartupWarning_IsLoggedOnce_AcrossMultipleCalls()
    {
        CapturingLogger<StaticKeyEncryptionProvider> logger = new();
        StaticKeyEncryptionProvider provider = CreateProvider(logger: logger);

        byte[] dek = RandomNumberGenerator.GetBytes(32);
        WrappedKey wrapped = await provider.WrapAsync(dek);
        _ = await provider.WrapAsync(dek);
        _ = await provider.UnwrapAsync(wrapped);

        logger.Entries
            .Count(entry => entry.Level == LogLevel.Warning &&
                            entry.Message.Contains("DEVELOPMENT USE ONLY", StringComparison.Ordinal))
            .Should().Be(1);
    }

    [Fact]
    public async Task WarningMessage_NeverContainsTheBase64Key()
    {
        CapturingLogger<StaticKeyEncryptionProvider> logger = new();
        StaticKeyEncryptionProvider provider = CreateProvider(logger: logger);

        byte[] dek = RandomNumberGenerator.GetBytes(32);
        _ = await provider.WrapAsync(dek);

        string kekBase64 = Convert.ToBase64String(_kek32);
        logger.Entries.Should().OnlyContain(entry =>
            !entry.Message.Contains(kekBase64, StringComparison.Ordinal));
    }
}
