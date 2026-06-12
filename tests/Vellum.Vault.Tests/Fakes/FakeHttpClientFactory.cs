namespace Vellum.Vault.Tests.Fakes;

/// <summary>
/// An <see cref="IHttpClientFactory"/> that hands out <see cref="HttpClient"/> instances bound
/// to a test-supplied <see cref="HttpMessageHandler"/>, recording every requested client name.
/// </summary>
public sealed class FakeHttpClientFactory(HttpMessageHandler handler, Uri baseAddress) : IHttpClientFactory
{
    private readonly HttpMessageHandler _handler = handler ?? throw new ArgumentNullException(nameof(handler));
    private readonly Uri _baseAddress = baseAddress ?? throw new ArgumentNullException(nameof(baseAddress));

    /// <summary>Every client name passed to <see cref="CreateClient"/>, in order.</summary>
    public List<string> CreatedClientNames { get; } = [];

    public HttpClient CreateClient(string name)
    {
        CreatedClientNames.Add(name);

        // disposeHandler: false — the handler is owned by the test and shared across clients,
        // mirroring how IHttpClientFactory pools handlers underneath disposable HttpClients.
        return new HttpClient(_handler, disposeHandler: false) { BaseAddress = _baseAddress };
    }
}
