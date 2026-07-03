using System.Net;
using FluentAssertions;
using Vellum.Vault.Tests.Fakes;
using Xunit;

namespace Vellum.Vault.Tests;

public sealed class VaultAuthenticationHandlerTests
{
    private const string _tokenHeader = "X-Vault-Token";

    private static HttpClient CreateClient(FakeVaultTokenProvider tokenProvider, FakeHttpMessageHandler inner)
    {
        VaultAuthenticationHandler authHandler = new(tokenProvider) { InnerHandler = inner };
        return new HttpClient(authHandler) { BaseAddress = new Uri("http://vault.test:8200/") };
    }

    private static string TokenOf(HttpRequestMessage request) =>
        request.Headers.GetValues(_tokenHeader).Single();

    [Fact]
    public async Task SendAsync_SetsTokenHeader_OnEveryRequest()
    {
        FakeVaultTokenProvider tokenProvider = new("hvs.t1");
        FakeHttpMessageHandler inner = new((request, ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        using HttpClient client = CreateClient(tokenProvider, inner);

        using HttpResponseMessage first = await client.GetAsync(new Uri("v1/x", UriKind.Relative));
        using HttpResponseMessage second = await client.GetAsync(new Uri("v1/y", UriKind.Relative));

        inner.CapturedRequests.Should().HaveCount(2);
        TokenOf(inner.CapturedRequests[0]).Should().Be("hvs.t1");
        TokenOf(inner.CapturedRequests[1]).Should().Be("hvs.t1");
        tokenProvider.GetTokenCallCount.Should().Be(2, "the token is fetched per request, never cached in headers");
    }

    [Fact]
    public async Task SendAsync_Success_DoesNotInvalidate()
    {
        FakeVaultTokenProvider tokenProvider = new("hvs.t1");
        FakeHttpMessageHandler inner = new((request, ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        using HttpClient client = CreateClient(tokenProvider, inner);

        using HttpResponseMessage response = await client.GetAsync(new Uri("v1/x", UriKind.Relative));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        tokenProvider.InvalidateCount.Should().Be(0);
    }

    [Fact]
    public async Task SendAsync_403_InvalidatesAndRetriesOnceWithFreshToken()
    {
        FakeVaultTokenProvider tokenProvider = new("hvs.t1", "hvs.t2");

        // The retry re-sends the SAME HttpRequestMessage with a rewritten header, so the token
        // must be captured at send time — inspecting CapturedRequests afterwards would only
        // show the final header value on both entries.
        List<string> seenTokens = [];
        FakeHttpMessageHandler inner = new((request, ct) =>
        {
            string token = TokenOf(request);
            seenTokens.Add(token);
            HttpStatusCode status = token == "hvs.t1" ? HttpStatusCode.Forbidden : HttpStatusCode.OK;
            return Task.FromResult(new HttpResponseMessage(status));
        });
        using HttpClient client = CreateClient(tokenProvider, inner);

        using HttpResponseMessage response = await client.GetAsync(new Uri("v1/x", UriKind.Relative));

        response.StatusCode.Should().Be(HttpStatusCode.OK, "the single retry with a fresh token must succeed");
        seenTokens.Should().Equal("hvs.t1", "hvs.t2");
        tokenProvider.InvalidateCount.Should().Be(1);
    }

    [Fact]
    public async Task SendAsync_403Twice_PropagatesSecond403()
    {
        FakeVaultTokenProvider tokenProvider = new("hvs.t1", "hvs.t2");
        FakeHttpMessageHandler inner = new((request, ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)));
        using HttpClient client = CreateClient(tokenProvider, inner);

        using HttpResponseMessage response = await client.GetAsync(new Uri("v1/x", UriKind.Relative));

        response.StatusCode.Should().Be(
            HttpStatusCode.Forbidden,
            "the handler covers token expiry, not authorization failures — a second 403 propagates");
        inner.CapturedRequests.Should().HaveCount(2, "exactly ONE retry, never more");
    }

    [Fact]
    public async Task SendAsync_403_FreshTokenIdentical_SkipsRetry()
    {
        // Scripting the same token twice simulates StaticVaultTokenProvider: invalidation
        // yields the identical credential.
        FakeVaultTokenProvider tokenProvider = new("hvs.t1", "hvs.t1");
        FakeHttpMessageHandler inner = new((request, ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)));
        using HttpClient client = CreateClient(tokenProvider, inner);

        using HttpResponseMessage response = await client.GetAsync(new Uri("v1/x", UriKind.Relative));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        inner.CapturedRequests.Should().HaveCount(
            1,
            "retrying with the identical token would only duplicate the failing request");
        tokenProvider.InvalidateCount.Should().Be(1);
    }
}
