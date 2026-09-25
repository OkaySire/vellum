using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum.Vault.Tests.Fakes;
using Xunit;

namespace Vellum.Vault.Tests;

/// <summary>
/// Covers <see cref="VaultOptions.TransitMount"/>: the Transit engine mount is configurable, so a
/// deployment can give each product or zone its own <c>transit/</c> mount on a shared Vault
/// cluster instead of the single hard-coded <c>transit</c> path of Vellum 0.2.x.
/// </summary>
public sealed class VaultTransitMountTests
{
    private static VaultOptions BaseOptions() => new()
    {
        Address = "http://vault.test:8200",
        Token = "hvs.test-token",
        KeyName = "test-key",
        HttpTimeout = TimeSpan.FromSeconds(10),
    };

    private static VaultKeyEncryptionProvider CreateProvider(
        FakeHttpMessageHandler handler,
        VaultOptions options)
    {
        HttpClient httpClient = new(handler)
        {
            BaseAddress = new Uri(options.Address.EndsWith('/') ? options.Address : options.Address + "/"),
            Timeout = options.HttpTimeout,
        };

        return new VaultKeyEncryptionProvider(
            httpClient,
            Options.Create(options),
            NullLogger<VaultKeyEncryptionProvider>.Instance);
    }

    private static FakeHttpMessageHandler CiphertextHandler() =>
        new((request, ct) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { data = new { ciphertext = "vault:v1:AbCdEf==" } }),
                    Encoding.UTF8,
                    "application/json"),
            }));

    private static FakeHttpMessageHandler PlaintextHandler(byte[] dek) =>
        new((request, ct) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { data = new { plaintext = Convert.ToBase64String(dek) } }),
                    Encoding.UTF8,
                    "application/json"),
            }));

    private static readonly byte[] _dek =
    [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    ];

    // ---------------------------------------------------------------------
    // Default — the 0.2.x path is preserved bit for bit
    // ---------------------------------------------------------------------

    [Fact]
    public void TransitMount_DefaultsToTransit()
    {
        VaultOptions options = new();

        options.TransitMount.Should().Be("transit");
    }

    [Fact]
    public async Task WrapAsync_DefaultMount_UsesTransitPath()
    {
        FakeHttpMessageHandler handler = CiphertextHandler();
        VaultKeyEncryptionProvider provider = CreateProvider(handler, BaseOptions());

        await provider.WrapAsync(_dek);

        handler.CapturedRequests[0].RequestUri!.AbsoluteUri
            .Should().Be("http://vault.test:8200/v1/transit/encrypt/test-key");
    }

    // ---------------------------------------------------------------------
    // The configured mount reaches every one of the three operations
    // ---------------------------------------------------------------------

    [Fact]
    public async Task WrapAsync_CustomMount_UsesConfiguredMount()
    {
        VaultOptions options = BaseOptions();
        options.TransitMount = "transit-zone-b";

        FakeHttpMessageHandler handler = CiphertextHandler();
        VaultKeyEncryptionProvider provider = CreateProvider(handler, options);

        await provider.WrapAsync(_dek);

        handler.CapturedRequests[0].RequestUri!.AbsoluteUri
            .Should().Be("http://vault.test:8200/v1/transit-zone-b/encrypt/test-key");
    }

    [Fact]
    public async Task UnwrapAsync_CustomMount_UsesConfiguredMount()
    {
        VaultOptions options = BaseOptions();
        options.TransitMount = "transit-zone-b";

        FakeHttpMessageHandler handler = PlaintextHandler(_dek);
        VaultKeyEncryptionProvider provider = CreateProvider(handler, options);

        await provider.UnwrapAsync(new WrappedKey("vault:v1:AbCdEf==", "v1"));

        handler.CapturedRequests[0].RequestUri!.AbsoluteUri
            .Should().Be("http://vault.test:8200/v1/transit-zone-b/decrypt/test-key");
    }

    [Fact]
    public async Task RewrapAsync_CustomMount_UsesConfiguredMount()
    {
        VaultOptions options = BaseOptions();
        options.TransitMount = "transit-zone-b";

        FakeHttpMessageHandler handler = CiphertextHandler();
        VaultKeyEncryptionProvider provider = CreateProvider(handler, options);

        await provider.RewrapAsync(new WrappedKey("vault:v1:AbCdEf==", "v1"));

        handler.CapturedRequests[0].RequestUri!.AbsoluteUri
            .Should().Be("http://vault.test:8200/v1/transit-zone-b/rewrap/test-key");
    }

    // ---------------------------------------------------------------------
    // Normalisation and escaping
    // ---------------------------------------------------------------------

    [Theory]
    [InlineData("transit-zone-b")]
    [InlineData("/transit-zone-b")]
    [InlineData("transit-zone-b/")]
    [InlineData("/transit-zone-b/")]
    [InlineData("  transit-zone-b  ")]
    public async Task WrapAsync_SurroundingSlashesOrSpaces_AreNormalised(string mount)
    {
        VaultOptions options = BaseOptions();
        options.TransitMount = mount;

        FakeHttpMessageHandler handler = CiphertextHandler();
        VaultKeyEncryptionProvider provider = CreateProvider(handler, options);

        await provider.WrapAsync(_dek);

        handler.CapturedRequests[0].RequestUri!.AbsoluteUri
            .Should().Be("http://vault.test:8200/v1/transit-zone-b/encrypt/test-key");
    }

    /// <summary>
    /// A nested mount keeps its internal <c>/</c> as a path separator. Escaping the mount as a
    /// single data string would emit <c>zone-b%2Ftransit</c>, which Vault answers with a 404 that
    /// names no cause — hence the segment-by-segment escaping, as in
    /// <c>AppRoleVaultTokenProvider.BuildLoginPath</c>.
    /// </summary>
    [Fact]
    public async Task WrapAsync_NestedMount_KeepsInternalSlashAsSeparator()
    {
        VaultOptions options = BaseOptions();
        options.TransitMount = "zone-b/transit";

        FakeHttpMessageHandler handler = CiphertextHandler();
        VaultKeyEncryptionProvider provider = CreateProvider(handler, options);

        await provider.WrapAsync(_dek);

        // AbsoluteUri, not ToString(): ToString() decodes %20 back to a space, while AbsoluteUri
        // shows the form actually put on the wire. (%2F survives both, but the wire form is the
        // thing under test.)
        string uri = handler.CapturedRequests[0].RequestUri!.AbsoluteUri;
        uri.Should().Be("http://vault.test:8200/v1/zone-b/transit/encrypt/test-key");
        uri.Should().NotContain("%2F", "an internal slash must stay a separator, not be escaped");
    }

    [Fact]
    public async Task WrapAsync_MountWithReservedCharacter_EscapesTheSegment()
    {
        VaultOptions options = BaseOptions();
        options.TransitMount = "zone b/transit";

        FakeHttpMessageHandler handler = CiphertextHandler();
        VaultKeyEncryptionProvider provider = CreateProvider(handler, options);

        await provider.WrapAsync(_dek);

        handler.CapturedRequests[0].RequestUri!.AbsoluteUri
            .Should().Be("http://vault.test:8200/v1/zone%20b/transit/encrypt/test-key");
    }

    /// <summary>
    /// Fail closed (design principle 5): a provider built by hand bypasses
    /// <c>VaultOptionsValidator</c>, so an empty mount must throw here rather than issue
    /// <c>v1//encrypt/key</c> and let Vault answer a 404 that names no cause.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("/")]
    [InlineData("//")]
    public async Task WrapAsync_EmptyMount_ThrowsBeforeAnyHttpCall(string mount)
    {
        VaultOptions options = BaseOptions();
        options.TransitMount = mount;

        FakeHttpMessageHandler handler = CiphertextHandler();
        VaultKeyEncryptionProvider provider = CreateProvider(handler, options);

        Func<Task> act = () => provider.WrapAsync(_dek);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .Where(ex => ex.Message.Contains("TransitMount", StringComparison.Ordinal));
        handler.CapturedRequests.Should().BeEmpty();
    }

    // ---------------------------------------------------------------------
    // The test that decides the batch: two providers, two mounts, same test
    // ---------------------------------------------------------------------

    /// <summary>
    /// Proves that two <see cref="VaultKeyEncryptionProvider"/> instances with different
    /// <see cref="VaultOptions.TransitMount"/> values coexist in the same process without any DI
    /// support (no named options, no keyed services): the whole assembly — the provider, its
    /// primary constructor, <see cref="VaultOptions"/> — is public, so a consumer can compose the
    /// instances by hand.
    /// </summary>
    /// <remarks>
    /// The assertion that carries the proof is that the two captured URIs <b>differ</b>. A test
    /// that only checked "the second URI contains transit-zone-b" would also pass if both
    /// instances shared one configuration.
    /// </remarks>
    [Fact]
    public async Task TwoProviders_DifferentMounts_EachCallsItsOwnMount()
    {
        VaultOptions optionsA = BaseOptions();
        optionsA.KeyName = "kek-a";
        optionsA.TransitMount = "transit";

        VaultOptions optionsB = BaseOptions();
        optionsB.KeyName = "kek-b";
        optionsB.TransitMount = "transit-zone-b";

        FakeHttpMessageHandler handlerA = CiphertextHandler();
        FakeHttpMessageHandler handlerB = CiphertextHandler();

        VaultKeyEncryptionProvider providerA = CreateProvider(handlerA, optionsA);
        VaultKeyEncryptionProvider providerB = CreateProvider(handlerB, optionsB);

        await providerA.WrapAsync(_dek);
        await providerB.WrapAsync(_dek);

        string uriA = handlerA.CapturedRequests.Should().ContainSingle().Which.RequestUri!.AbsoluteUri;
        string uriB = handlerB.CapturedRequests.Should().ContainSingle().Which.RequestUri!.AbsoluteUri;

        // The control that matters: the two instances are not sharing one configuration.
        uriA.Should().NotBe(uriB);

        uriA.Should().Be("http://vault.test:8200/v1/transit/encrypt/kek-a");
        uriB.Should().Be("http://vault.test:8200/v1/transit-zone-b/encrypt/kek-b");
    }

    /// <summary>
    /// Same coexistence check, but with both providers sharing a single fake handler: it proves
    /// the two mounts are honoured per instance rather than per handler, and the ordering of the
    /// two captured URIs makes a shared-configuration bug impossible to hide.
    /// </summary>
    [Fact]
    public async Task TwoProviders_SharedHandler_CaptureTwoDistinctMounts()
    {
        FakeHttpMessageHandler handler = CiphertextHandler();

        VaultOptions optionsA = BaseOptions();
        optionsA.TransitMount = "transit-zone-a";

        VaultOptions optionsB = BaseOptions();
        optionsB.TransitMount = "transit-zone-b";

        VaultKeyEncryptionProvider providerA = CreateProvider(handler, optionsA);
        VaultKeyEncryptionProvider providerB = CreateProvider(handler, optionsB);

        await providerA.WrapAsync(_dek);
        await providerB.WrapAsync(_dek);

        handler.CapturedRequests.Should().HaveCount(2);
        string first = handler.CapturedRequests[0].RequestUri!.AbsoluteUri;
        string second = handler.CapturedRequests[1].RequestUri!.AbsoluteUri;

        first.Should().NotBe(second);
        first.Should().Be("http://vault.test:8200/v1/transit-zone-a/encrypt/test-key");
        second.Should().Be("http://vault.test:8200/v1/transit-zone-b/encrypt/test-key");
    }
}
