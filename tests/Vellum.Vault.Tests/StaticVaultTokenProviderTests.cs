using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Vellum.Vault.Tests;

public sealed class StaticVaultTokenProviderTests
{
    private static StaticVaultTokenProvider CreateProvider(string token = "hvs.static") =>
        new(Options.Create(new VaultOptions
        {
            Address = "https://vault.test:8200",
            Token = token,
            KeyName = "test-key",
        }));

    [Fact]
    public async Task GetTokenAsync_ReturnsConfiguredToken()
    {
        StaticVaultTokenProvider provider = CreateProvider("hvs.my-token");

        string token = await provider.GetTokenAsync(CancellationToken.None);

        token.Should().Be("hvs.my-token");
    }

    [Fact]
    public async Task InvalidateToken_IsNoOp_NextCallReturnsSameToken()
    {
        StaticVaultTokenProvider provider = CreateProvider("hvs.my-token");

        provider.InvalidateToken();
        string token = await provider.GetTokenAsync(CancellationToken.None);

        token.Should().Be("hvs.my-token", "a static token has no re-acquisition path");
    }
}
