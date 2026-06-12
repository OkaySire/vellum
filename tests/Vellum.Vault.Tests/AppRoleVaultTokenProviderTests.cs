using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Vellum.Vault.Tests.Fakes;
using Xunit;

namespace Vellum.Vault.Tests;

public sealed class AppRoleVaultTokenProviderTests
{
    private static readonly Uri _baseAddress = new("http://vault.test:8200/");

    private static VaultOptions AppRoleOptions(
        double threshold = 0.8,
        string mount = "approle") => new()
    {
        Address = "http://vault.test:8200",
        KeyName = "test-key",
        AuthMethod = VaultAuthMethod.AppRole,
        RoleId = "role-123",
        SecretId = "secret-456",
        AppRoleMount = mount,
        TokenRenewalThreshold = threshold,
        AllowInsecureHttp = true,
    };

    private static AppRoleVaultTokenProvider CreateProvider(
        FakeHttpMessageHandler handler,
        VaultOptions? options = null,
        TimeProvider? timeProvider = null) =>
        new(
            new FakeHttpClientFactory(handler, _baseAddress),
            Options.Create(options ?? AppRoleOptions()),
            timeProvider ?? TimeProvider.System,
            NullLogger<AppRoleVaultTokenProvider>.Instance);

    private static HttpResponseMessage LoginOk(string clientToken, long leaseDurationSeconds = 3600)
    {
        string json = string.Create(
            CultureInfo.InvariantCulture,
            $"{{\"auth\":{{\"client_token\":\"{clientToken}\",\"lease_duration\":{leaseDurationSeconds},\"renewable\":true}}}}");
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }

    [Fact]
    public async Task GetTokenAsync_FirstCall_LogsInWithRoleIdAndSecretId()
    {
        FakeHttpMessageHandler handler = new((request, ct) => Task.FromResult(LoginOk("hvs.t1")));
        using AppRoleVaultTokenProvider provider = CreateProvider(handler);

        string token = await provider.GetTokenAsync(CancellationToken.None);

        token.Should().Be("hvs.t1");
        handler.CapturedRequests.Should().HaveCount(1);
        HttpRequestMessage request = handler.CapturedRequests[0];
        request.Method.Should().Be(HttpMethod.Post);
        // L17: AbsoluteUri is the on-the-wire form; ToString() decanonicalises %HH sequences.
        request.RequestUri!.AbsoluteUri.Should().Be("http://vault.test:8200/v1/auth/approle/login");

        using JsonDocument body = JsonDocument.Parse(handler.CapturedRequestBodies[0]);
        body.RootElement.GetProperty("role_id").GetString().Should().Be("role-123");
        body.RootElement.GetProperty("secret_id").GetString().Should().Be("secret-456");
    }

    [Fact]
    public async Task GetTokenAsync_SecondCall_UsesCachedToken_NoSecondLogin()
    {
        FakeHttpMessageHandler handler = new((request, ct) => Task.FromResult(LoginOk("hvs.t1")));
        using AppRoleVaultTokenProvider provider = CreateProvider(handler);

        string first = await provider.GetTokenAsync(CancellationToken.None);
        string second = await provider.GetTokenAsync(CancellationToken.None);

        first.Should().Be("hvs.t1");
        second.Should().Be("hvs.t1");
        handler.CapturedRequests.Should().HaveCount(1, "the cached token must be reused");
    }

    [Fact]
    public async Task GetTokenAsync_BeforeRenewalThreshold_DoesNotReLogin()
    {
        FakeTimeProvider time = new();
        int loginCount = 0;
        FakeHttpMessageHandler handler = new((request, ct) =>
        {
            loginCount++;
            return Task.FromResult(LoginOk("hvs.t" + loginCount.ToString(CultureInfo.InvariantCulture)));
        });
        using AppRoleVaultTokenProvider provider = CreateProvider(handler, timeProvider: time);

        _ = await provider.GetTokenAsync(CancellationToken.None);
        // lease 3600s × threshold 0.8 = refresh at +2880s. One second before: still cached.
        time.Advance(TimeSpan.FromSeconds(2879));
        string token = await provider.GetTokenAsync(CancellationToken.None);

        token.Should().Be("hvs.t1");
        handler.CapturedRequests.Should().HaveCount(1);
    }

    [Fact]
    public async Task GetTokenAsync_PastRenewalThreshold_ReLogins()
    {
        FakeTimeProvider time = new();
        int loginCount = 0;
        FakeHttpMessageHandler handler = new((request, ct) =>
        {
            loginCount++;
            return Task.FromResult(LoginOk("hvs.t" + loginCount.ToString(CultureInfo.InvariantCulture)));
        });
        using AppRoleVaultTokenProvider provider = CreateProvider(handler, timeProvider: time);

        _ = await provider.GetTokenAsync(CancellationToken.None);
        // lease 3600s × threshold 0.8 = refresh at +2880s. Cross the threshold.
        time.Advance(TimeSpan.FromSeconds(2881));
        string token = await provider.GetTokenAsync(CancellationToken.None);

        token.Should().Be("hvs.t2", "a token past its renewal threshold must be replaced by a fresh login");
        handler.CapturedRequests.Should().HaveCount(2);
    }

    [Fact]
    public async Task InvalidateToken_ForcesReLogin()
    {
        int loginCount = 0;
        FakeHttpMessageHandler handler = new((request, ct) =>
        {
            loginCount++;
            return Task.FromResult(LoginOk("hvs.t" + loginCount.ToString(CultureInfo.InvariantCulture)));
        });
        using AppRoleVaultTokenProvider provider = CreateProvider(handler);

        string first = await provider.GetTokenAsync(CancellationToken.None);
        provider.InvalidateToken();
        string second = await provider.GetTokenAsync(CancellationToken.None);

        first.Should().Be("hvs.t1");
        second.Should().Be("hvs.t2");
        handler.CapturedRequests.Should().HaveCount(2);
    }

    [Fact]
    public async Task GetTokenAsync_ConcurrentCallers_ShareSingleLogin()
    {
        FakeHttpMessageHandler handler = new(async (request, ct) =>
        {
            // A small delay widens the race window so all callers really overlap the login.
            await Task.Delay(50, ct);
            return LoginOk("hvs.t1");
        });
        using AppRoleVaultTokenProvider provider = CreateProvider(handler);

        Task<string>[] callers = Enumerable.Range(0, 10)
            .Select(_ => Task.Run(() => provider.GetTokenAsync(CancellationToken.None).AsTask()))
            .ToArray();
        string[] tokens = await Task.WhenAll(callers);

        tokens.Should().AllBe("hvs.t1");
        handler.CapturedRequests.Should().HaveCount(1, "concurrent callers must share one login round-trip");
    }

    [Fact]
    public async Task GetTokenAsync_LoginFails_Throws_WithoutLeakingCredentials()
    {
        FakeHttpMessageHandler handler = new((request, ct) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("{\"errors\":[\"invalid role or secret ID\"]}", Encoding.UTF8, "application/json"),
            }));
        using AppRoleVaultTokenProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.GetTokenAsync(CancellationToken.None);

        InvalidOperationException ex = (await act.Should().ThrowAsync<InvalidOperationException>()).Which;
        ex.Message.Should().Contain("400", "fail closed with the HTTP status for diagnostics");
        ex.Message.Should().NotContain("role-123", "the role id must never appear in exception messages");
        ex.Message.Should().NotContain("secret-456", "the secret id must never appear in exception messages");
    }

    [Fact]
    public async Task GetTokenAsync_MissingClientToken_Throws()
    {
        FakeHttpMessageHandler handler = new((request, ct) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "{\"auth\":{\"client_token\":\"\",\"lease_duration\":3600,\"renewable\":true}}",
                    Encoding.UTF8,
                    "application/json"),
            }));
        using AppRoleVaultTokenProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.GetTokenAsync(CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>("fail closed on a login response without a token");
    }

    [Fact]
    public async Task GetTokenAsync_LeaseDurationZero_TokenNeverRefreshes()
    {
        FakeTimeProvider time = new();
        FakeHttpMessageHandler handler = new((request, ct) => Task.FromResult(LoginOk("hvs.t1", leaseDurationSeconds: 0)));
        using AppRoleVaultTokenProvider provider = CreateProvider(handler, timeProvider: time);

        _ = await provider.GetTokenAsync(CancellationToken.None);
        time.Advance(TimeSpan.FromDays(3650));
        string token = await provider.GetTokenAsync(CancellationToken.None);

        token.Should().Be("hvs.t1", "lease_duration 0 means a non-expiring token (Vault semantics)");
        handler.CapturedRequests.Should().HaveCount(1);
    }

    [Fact]
    public async Task GetTokenAsync_NestedMount_EscapesEachSegmentKeepingSlashes()
    {
        FakeHttpMessageHandler handler = new((request, ct) => Task.FromResult(LoginOk("hvs.t1")));
        using AppRoleVaultTokenProvider provider = CreateProvider(handler, AppRoleOptions(mount: "team a/approle"));

        _ = await provider.GetTokenAsync(CancellationToken.None);

        handler.CapturedRequests[0].RequestUri!.AbsoluteUri
            .Should().Be("http://vault.test:8200/v1/auth/team%20a/approle/login");
    }
}
