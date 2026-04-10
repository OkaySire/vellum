using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using FluentAssertions.Specialized;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum.Vault.Tests.Fakes;
using Xunit;

namespace Vellum.Vault.Tests;

public sealed class VaultKeyEncryptionProviderTests
{
    private static readonly VaultOptions _defaultOptions = new()
    {
        Address = "http://vault.test:8200",
        Token = "hvs.test-token",
        KeyName = "test-key",
        HttpTimeout = TimeSpan.FromSeconds(10),
    };

    private static VaultKeyEncryptionProvider CreateProvider(
        FakeHttpMessageHandler handler,
        VaultOptions? options = null)
    {
        VaultOptions effective = options ?? _defaultOptions;
        HttpClient httpClient = new(handler)
        {
            BaseAddress = new Uri(effective.Address.EndsWith('/') ? effective.Address : effective.Address + "/"),
            Timeout = effective.HttpTimeout,
        };
        httpClient.DefaultRequestHeaders.Add("X-Vault-Token", effective.Token);

        return new VaultKeyEncryptionProvider(
            httpClient,
            Options.Create(effective),
            NullLogger<VaultKeyEncryptionProvider>.Instance);
    }

    private static HttpResponseMessage Ok(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };

    private static HttpResponseMessage JsonOk<T>(T payload) =>
        Ok(JsonSerializer.Serialize(payload));

    // ---------------------------------------------------------------------
    // Wrap
    // ---------------------------------------------------------------------

    [Fact]
    public async Task WrapAsync_ValidDek_ReturnsWrappedKey()
    {
        byte[] dek = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        string dekBase64 = Convert.ToBase64String(dek);

        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(JsonOk(new { data = new { ciphertext = "vault:v1:AbCdEf==" } })));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        WrappedKey wrapped = await provider.WrapAsync(dek);

        wrapped.Ciphertext.Should().Be("vault:v1:AbCdEf==");
        wrapped.ProviderVersion.Should().Be("v1");

        handler.CapturedRequests.Should().HaveCount(1);
        HttpRequestMessage request = handler.CapturedRequests[0];
        request.Method.Should().Be(HttpMethod.Post);
        request.RequestUri!.ToString().Should().Be("http://vault.test:8200/v1/transit/encrypt/test-key");
        request.Headers.GetValues("X-Vault-Token").Should().ContainSingle().Which.Should().Be("hvs.test-token");

        using JsonDocument body = JsonDocument.Parse(handler.CapturedRequestBodies[0]);
        body.RootElement.GetProperty("plaintext").GetString().Should().Be(dekBase64);
    }

    [Fact]
    public async Task WrapAsync_ProviderVersion_HandlesMultiDigitVersions()
    {
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(JsonOk(new { data = new { ciphertext = "vault:v42:payload==" } })));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        WrappedKey wrapped = await provider.WrapAsync(new byte[] { 1, 2, 3 });

        wrapped.ProviderVersion.Should().Be("v42");
        wrapped.Ciphertext.Should().Be("vault:v42:payload==");
    }

    [Fact]
    public async Task WrapAsync_KeyNameWithReservedChars_IsUrlEscaped()
    {
        VaultOptions options = new()
        {
            Address = _defaultOptions.Address,
            Token = _defaultOptions.Token,
            KeyName = "my key/with spaces",
            HttpTimeout = _defaultOptions.HttpTimeout,
        };

        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(JsonOk(new { data = new { ciphertext = "vault:v1:x==" } })));

        VaultKeyEncryptionProvider provider = CreateProvider(handler, options);

        _ = await provider.WrapAsync(new byte[] { 1, 2, 3 });

        // Compare the on-the-wire encoded form via AbsoluteUri rather than ToString(), which
        // canonicalises %20 back to a literal space for display purposes.
        handler.CapturedRequests[0].RequestUri!.AbsoluteUri
            .Should().Be("http://vault.test:8200/v1/transit/encrypt/my%20key%2Fwith%20spaces");
    }

    [Fact]
    public async Task WrapAsync_Non200_ThrowsInvalidOperationException()
    {
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                Content = new StringContent("{\"errors\":[\"permission denied\"]}", Encoding.UTF8, "application/json"),
            }));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.WrapAsync(new byte[] { 1, 2, 3 });

        await act.Should().ThrowAsync<InvalidOperationException>()
            .Where(ex => ex.Message.Contains("encrypt", StringComparison.Ordinal)
                         && ex.Message.Contains("403", StringComparison.Ordinal)
                         && ex.Message.Contains("permission denied", StringComparison.Ordinal));
    }

    [Fact]
    public async Task WrapAsync_HttpError_ThrowsHttpRequestException()
    {
        FakeHttpMessageHandler handler = new((request, ct) =>
            throw new HttpRequestException("connection refused"));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.WrapAsync(new byte[] { 1, 2, 3 });

        await act.Should().ThrowAsync<HttpRequestException>();
    }

    [Fact]
    public async Task WrapAsync_MalformedJson_ThrowsJsonException()
    {
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(Ok("this-is-not-json")));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.WrapAsync(new byte[] { 1, 2, 3 });

        await act.Should().ThrowAsync<JsonException>();
    }

    [Fact]
    public async Task WrapAsync_NullCiphertext_ThrowsInvalidOperationException()
    {
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(JsonOk(new { data = new { ciphertext = (string?)null } })));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.WrapAsync(new byte[] { 1, 2, 3 });

        await act.Should().ThrowAsync<InvalidOperationException>()
            .Where(ex => ex.Message.Contains("ciphertext", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task WrapAsync_EmptyDek_Throws()
    {
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(JsonOk(new { data = new { ciphertext = "vault:v1:x==" } })));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.WrapAsync(ReadOnlyMemory<byte>.Empty);

        await act.Should().ThrowAsync<ArgumentException>();
        handler.CapturedRequests.Should().BeEmpty();
    }

    [Theory]
    [InlineData("notvault:v1:abc")]
    [InlineData("vault:v:abc")]
    [InlineData("vault:vabc:payload")]
    [InlineData("vault:v1")]
    [InlineData("vault:v0:payload")]
    public async Task WrapAsync_MalformedCiphertextFormat_ThrowsInvalidOperationException(string ciphertext)
    {
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(JsonOk(new { data = new { ciphertext } })));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.WrapAsync(new byte[] { 1, 2, 3 });

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    // ---------------------------------------------------------------------
    // Unwrap
    // ---------------------------------------------------------------------

    [Fact]
    public async Task UnwrapAsync_ValidCiphertext_ReturnsDekBytes()
    {
        byte[] originalDek = [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9];
        string dekBase64 = Convert.ToBase64String(originalDek);

        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(JsonOk(new { data = new { plaintext = dekBase64 } })));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        byte[] dek = await provider.UnwrapAsync(new WrappedKey("vault:v1:irrelevant==", "v1"));

        dek.Should().BeEquivalentTo(originalDek);

        handler.CapturedRequests.Should().HaveCount(1);
        HttpRequestMessage request = handler.CapturedRequests[0];
        request.Method.Should().Be(HttpMethod.Post);
        request.RequestUri!.ToString().Should().Be("http://vault.test:8200/v1/transit/decrypt/test-key");

        using JsonDocument body = JsonDocument.Parse(handler.CapturedRequestBodies[0]);
        body.RootElement.GetProperty("ciphertext").GetString().Should().Be("vault:v1:irrelevant==");
    }

    [Fact]
    public async Task UnwrapAsync_NullWrappedKey_ThrowsArgumentNullException()
    {
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(JsonOk(new { data = new { plaintext = "" } })));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.UnwrapAsync(null!);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task UnwrapAsync_WrongFormat_ThrowsInvalidOperationException()
    {
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(JsonOk(new { data = new { plaintext = "AAAA" } })));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.UnwrapAsync(new WrappedKey("not-a-vault-ciphertext", "v1"));

        await act.Should().ThrowAsync<InvalidOperationException>()
            .Where(ex => ex.Message.Contains("vault:v", StringComparison.Ordinal));

        handler.CapturedRequests.Should().BeEmpty("because the format should be rejected before any HTTP call");
    }

    [Fact]
    public async Task UnwrapAsync_Non200_ThrowsAndBodyIsPropagatedInException()
    {
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent(
                    "{\"errors\":[\"invalid ciphertext: failed to base64-decode ciphertext\"]}",
                    Encoding.UTF8,
                    "application/json"),
            }));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.UnwrapAsync(new WrappedKey("vault:v1:corrupt==", "v1"));

        await act.Should().ThrowAsync<InvalidOperationException>()
            .Where(ex => ex.Message.Contains("decrypt", StringComparison.Ordinal)
                         && ex.Message.Contains("400", StringComparison.Ordinal)
                         && ex.Message.Contains("invalid ciphertext", StringComparison.Ordinal));
    }

    [Fact]
    public async Task UnwrapAsync_NullPlaintext_ThrowsInvalidOperationException()
    {
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(JsonOk(new { data = new { plaintext = (string?)null } })));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.UnwrapAsync(new WrappedKey("vault:v1:xyz==", "v1"));

        await act.Should().ThrowAsync<InvalidOperationException>()
            .Where(ex => ex.Message.Contains("plaintext", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task UnwrapAsync_MalformedBase64_ThrowsInvalidOperationException()
    {
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(JsonOk(new { data = new { plaintext = "!!!not-base64!!!" } })));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.UnwrapAsync(new WrappedKey("vault:v1:xyz==", "v1"));

        ExceptionAssertions<InvalidOperationException> caught = await act.Should().ThrowAsync<InvalidOperationException>();
        caught.Which.InnerException.Should().BeOfType<FormatException>();
    }

    [Fact]
    public async Task CancellationToken_Cancelled_ThrowsOperationCanceledException()
    {
        FakeHttpMessageHandler handler = new(async (request, ct) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
            return new HttpResponseMessage(HttpStatusCode.OK);
        });

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        using CancellationTokenSource cts = new();
        cts.Cancel();

        Func<Task> wrapAct = async () => await provider.WrapAsync(new byte[] { 1, 2, 3 }, cts.Token);
        Func<Task> unwrapAct = async () =>
            await provider.UnwrapAsync(new WrappedKey("vault:v1:xxx==", "v1"), cts.Token);

        await wrapAct.Should().ThrowAsync<OperationCanceledException>();
        await unwrapAct.Should().ThrowAsync<OperationCanceledException>();
    }

    // ---------------------------------------------------------------------
    // Roundtrip — end-to-end via a fake Vault that preserves the plaintext
    // ---------------------------------------------------------------------

    [Fact]
    public async Task WrapThenUnwrap_Roundtrip_ReturnsOriginalDek()
    {
        byte[] originalDek = new byte[32];
        for (int i = 0; i < originalDek.Length; i++)
        {
            originalDek[i] = (byte)(i * 7);
        }

        FakeHttpMessageHandler handler = new((request, ct) =>
            FakeVaultAsync(request, ct));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        WrappedKey wrapped = await provider.WrapAsync(originalDek);
        byte[] roundtripped = await provider.UnwrapAsync(wrapped);

        roundtripped.Should().BeEquivalentTo(originalDek);
        wrapped.ProviderVersion.Should().Be("v1");
        wrapped.Ciphertext.Should().StartWith("vault:v1:");
    }

    private static Task<HttpResponseMessage> FakeVaultAsync(HttpRequestMessage request, CancellationToken ct)
    {
        string path = request.RequestUri!.AbsolutePath;
        if (path.Contains("/encrypt/", StringComparison.Ordinal))
        {
            string body = request.Content!.ReadAsStringAsync(ct).GetAwaiter().GetResult();
            using JsonDocument doc = JsonDocument.Parse(body);
            string plaintext = doc.RootElement.GetProperty("plaintext").GetString()!;
            string ciphertext = "vault:v1:" + plaintext;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { data = new { ciphertext } }),
                    Encoding.UTF8,
                    "application/json"),
            });
        }

        if (path.Contains("/decrypt/", StringComparison.Ordinal))
        {
            string body = request.Content!.ReadAsStringAsync(ct).GetAwaiter().GetResult();
            using JsonDocument doc = JsonDocument.Parse(body);
            string ciphertext = doc.RootElement.GetProperty("ciphertext").GetString()!;
            const string prefix = "vault:v1:";
            string plaintext = ciphertext.StartsWith(prefix, StringComparison.Ordinal)
                ? ciphertext[prefix.Length..]
                : throw new InvalidOperationException("unexpected ciphertext in fake vault");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { data = new { plaintext } }),
                    Encoding.UTF8,
                    "application/json"),
            });
        }

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }

    // ---------------------------------------------------------------------
    // H-2 — error body truncation
    // ---------------------------------------------------------------------

    [Fact]
    public async Task WrapAsync_LargeErrorBody_IsTruncatedInExceptionMessage()
    {
        // H-2: a huge error body (e.g. an HTML page from a misrouted proxy) must not be
        // embedded verbatim in the exception message. The truncated body keeps diagnostics
        // useful without turning the exception into a vector for attacker-controlled content.
        string oversizedBody = new string('A', 100_000);
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError)
            {
                Content = new StringContent(oversizedBody, Encoding.UTF8, "text/html"),
            }));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.WrapAsync(new byte[] { 1, 2, 3 });

        ExceptionAssertions<InvalidOperationException> caught =
            await act.Should().ThrowAsync<InvalidOperationException>();

        caught.Which.Message.Length.Should().BeLessThan(1_000,
            "the oversized body must be truncated before embedding into the exception");
        caught.Which.Message.Should().Contain("truncated");
        caught.Which.Message.Should().Contain("100000");
    }

    [Fact]
    public async Task UnwrapAsync_LargeErrorBody_IsTruncatedInExceptionMessage()
    {
        // H-2 symmetry on the decrypt path.
        string oversizedBody = new string('B', 50_000);
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadGateway)
            {
                Content = new StringContent(oversizedBody, Encoding.UTF8, "text/plain"),
            }));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.UnwrapAsync(new WrappedKey("vault:v1:xxx==", "v1"));

        ExceptionAssertions<InvalidOperationException> caught =
            await act.Should().ThrowAsync<InvalidOperationException>();

        caught.Which.Message.Length.Should().BeLessThan(1_000);
        caught.Which.Message.Should().Contain("truncated");
        caught.Which.Message.Should().Contain("50000");
    }

    [Fact]
    public async Task WrapAsync_SmallErrorBody_IsNotMarkedAsTruncated()
    {
        // Regression guard: short bodies pass through unchanged so operators still see
        // the full Vault error verbatim.
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                Content = new StringContent(
                    "{\"errors\":[\"permission denied\"]}",
                    Encoding.UTF8,
                    "application/json"),
            }));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.WrapAsync(new byte[] { 1, 2, 3 });

        ExceptionAssertions<InvalidOperationException> caught =
            await act.Should().ThrowAsync<InvalidOperationException>();

        caught.Which.Message.Should().Contain("permission denied");
        caught.Which.Message.Should().NotContain("truncated",
            "short bodies must pass through without the truncation marker");
    }

    [Fact]
    public void ProviderName_IsVault()
    {
        FakeHttpMessageHandler handler = new((request, ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        provider.ProviderName.Should().Be("vault");
    }
}
