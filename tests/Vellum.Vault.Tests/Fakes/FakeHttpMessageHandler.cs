namespace Vellum.Vault.Tests.Fakes;

/// <summary>
/// A test <see cref="HttpMessageHandler"/> that records every request it receives and lets the
/// test author supply the response via a handler delegate. Lets us make black-box assertions on
/// outgoing requests (method, URL, body, headers) and on the provider's behaviour for any
/// response shape without needing a live Vault instance.
/// </summary>
public sealed class FakeHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responder)
    : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _responder =
        responder ?? throw new ArgumentNullException(nameof(responder));

    /// <summary>
    /// Every request that flowed through this handler, in order. Useful for assertions on
    /// header propagation, URL construction, and call counts.
    /// </summary>
    public List<HttpRequestMessage> CapturedRequests { get; } = [];

    /// <summary>
    /// Every request body that flowed through this handler, buffered as a string, in order.
    /// The body is read eagerly so tests can inspect it even after the response has been
    /// returned (and after the original content stream has been disposed).
    /// </summary>
    public List<string> CapturedRequestBodies { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        CapturedRequests.Add(request);

        if (request.Content is not null)
        {
            string body = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            CapturedRequestBodies.Add(body);
        }
        else
        {
            CapturedRequestBodies.Add(string.Empty);
        }

        return await _responder(request, cancellationToken).ConfigureAwait(false);
    }
}
