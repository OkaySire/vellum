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
/// Executable record of the four Vault Transit responses measured by infra on a live Vault while
/// designing the 0.4.0 store-first decrypt: two Transit mounts, a ciphertext from one presented to
/// the other.
/// </summary>
/// <remarks>
/// <para>
/// | Case | Response |
/// | --- | --- |
/// | wrong mount (the case to detect) | <c>400</c> — <c>cipher: message authentication failed</c> |
/// | key does not exist (a real outage) | <c>400</c> — <c>encryption key not found</c> |
/// | permission refused | <c>403</c> — <c>permission denied</c> |
/// | witness, its own mount | success |
/// </para>
/// <para>
/// <b>Why this is pinned even though Vellum no longer reads it.</b> The status code does not
/// separate the first two cases — only the wording does. That is precisely why 0.4.0 resolves the
/// DEK from the key store first instead of detecting a wrong-mount reply: the class of error
/// disappears rather than being recognised, and nothing in Vellum keys off a Vault message. These
/// tests assert the consequence of that decision — all three failures reach Vellum as the same
/// exception type, so no caller could branch on them even if it wanted to — and keep the measured
/// table from being lost to a plan document nobody re-reads.
/// </para>
/// <para>
/// <b>Known gap.</b> The exact Vault build these four responses were observed on was not recorded
/// alongside the measurement (dated 2026-09-25). The wording of a Vault error is version-specific,
/// so if this table is ever used for anything beyond "the wording is the only discriminator, do not
/// rely on it", the version has to be obtained from infra first.
/// </para>
/// </remarks>
public sealed class VaultMountMismatchResponseTests
{
    /// <summary>The wrong-mount reply: this is the case the 0.4.0 reordering removes the need to detect.</summary>
    public const string WrongMountBody = """{"errors":["cipher: message authentication failed"]}""";

    /// <summary>A genuinely missing Transit key — same HTTP status as the wrong-mount case above.</summary>
    public const string KeyNotFoundBody = """{"errors":["encryption key not found"]}""";

    /// <summary>The policy refusal, the only one of the three that differs in status.</summary>
    public const string PermissionDeniedBody = """{"errors":["permission denied"]}""";

    private static readonly VaultOptions _options = new()
    {
        Address = "http://vault.test:8200",
        Token = "hvs.test-token",
        KeyName = "vellum-kek",
        TransitMount = "transit-zone-b",
        HttpTimeout = TimeSpan.FromSeconds(10),
    };

    private static VaultKeyEncryptionProvider CreateProvider(FakeHttpMessageHandler handler)
    {
        HttpClient httpClient = new(handler)
        {
            BaseAddress = new Uri(_options.Address + "/"),
            Timeout = _options.HttpTimeout,
        };
        httpClient.DefaultRequestHeaders.Add("X-Vault-Token", _options.Token);

        return new VaultKeyEncryptionProvider(
            httpClient,
            Options.Create(_options),
            NullLogger<VaultKeyEncryptionProvider>.Instance);
    }

    /// <summary>
    /// The three measured failures are indistinguishable by type: whatever Vault said, Vellum
    /// raises one <see cref="InvalidOperationException"/>, which is exactly what makes the
    /// store-first fallback in <c>PayloadEncryptor.DecryptAsync</c> able to catch on a type instead
    /// of on a message.
    /// </summary>
    [Theory]
    [InlineData((int)HttpStatusCode.BadRequest, WrongMountBody)]
    [InlineData((int)HttpStatusCode.BadRequest, KeyNotFoundBody)]
    [InlineData((int)HttpStatusCode.Forbidden, PermissionDeniedBody)]
    public async Task UnwrapAsync_MeasuredVaultFailures_AllSurfaceAsTheSameExceptionType(int status, string body)
    {
        FakeHttpMessageHandler handler = new((request, ct) => Task.FromResult(
            new HttpResponseMessage((HttpStatusCode)status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            }));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        Func<Task> act = async () => await provider.UnwrapAsync(new WrappedKey("vault:v1:AbCdEf==", "v1"));

        _ = await act.Should().ThrowAsync<InvalidOperationException>(
            "Vellum must not — and now does not — need to tell these three apart");
    }

    /// <summary>
    /// The discriminator, pinned: the wrong-mount reply and the missing-key reply carry the SAME
    /// HTTP status and differ only in wording. A fallback keyed on that wording would stop firing,
    /// silently, the day Vault rephrases it.
    /// </summary>
    [Fact]
    public void MeasuredVaultFailures_StatusCodeDoesNotSeparateWrongMountFromMissingKey()
    {
        // Same status for the case to detect and the case that is a real outage.
        const HttpStatusCode WrongMountStatus = HttpStatusCode.BadRequest;
        const HttpStatusCode KeyNotFoundStatus = HttpStatusCode.BadRequest;

        WrongMountStatus.Should().Be(KeyNotFoundStatus);
        WrongMountBody.Should().NotBe(KeyNotFoundBody, "the wording is the ONLY discriminator");
        WrongMountBody.Should().Contain("message authentication failed");
        KeyNotFoundBody.Should().Contain("encryption key not found");
    }

    /// <summary>
    /// The witness for the table above: on its own mount the very same call succeeds, so the three
    /// failing cases are genuine failures of the provider and not an artefact of a handler that
    /// could only ever fail.
    /// </summary>
    [Fact]
    public async Task UnwrapAsync_OwnMount_Succeeds()
    {
        byte[] dek = new byte[32];
        for (int i = 0; i < dek.Length; i++)
        {
            dek[i] = (byte)i;
        }

        FakeHttpMessageHandler handler = new((request, ct) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { data = new { plaintext = Convert.ToBase64String(dek) } }),
                    Encoding.UTF8,
                    "application/json"),
            }));

        VaultKeyEncryptionProvider provider = CreateProvider(handler);

        byte[] unwrapped = await provider.UnwrapAsync(new WrappedKey("vault:v1:AbCdEf==", "v1"));

        unwrapped.Should().Equal(dek);
        handler.CapturedRequests.Should().ContainSingle()
            .Which.RequestUri!.ToString().Should().Be("http://vault.test:8200/v1/transit-zone-b/decrypt/vellum-kek");
    }
}
