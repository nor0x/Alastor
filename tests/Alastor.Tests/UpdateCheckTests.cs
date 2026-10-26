using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Alastor.Server;
using Alastor.Server.Services.Updates;

namespace Alastor.Tests;

public sealed class UpdateCheckTests
{
    [Theory]
    [InlineData("0.1.0", "v0.2.0", true)]
    [InlineData("0.1.0", "0.1.1", true)]
    [InlineData("0.2.0", "v0.2.0", false)]
    [InlineData("0.2", "v0.2.0", false)]
    [InlineData("0.3.0", "v0.2.0", false)]
    [InlineData("0.2.0-rc1", "v0.2.0", true)]
    [InlineData("0.2.0", "v0.2.0-rc1", false)]
    [InlineData("0.2.0+abc123", "v0.2.0", false)]
    [InlineData("dev", "v0.2.0", false)]
    [InlineData("0.1.0", "nightly", false)]
    public void Compares_release_tags_with_the_running_version(string current, string tag, bool newer) =>
        Assert.Equal(newer, UpdateCheckService.IsNewer(current, tag));

    [Fact]
    public async Task Latest_release_links_to_its_page_on_github()
    {
        var http = new StubHandler(HttpStatusCode.OK, """{"tag_name":"v0.3.0","html_url":"https://evil.example/","published_at":"2026-10-20T12:00:00Z"}""");
        var svc = Create(http);

        await svc.CheckAsync(CancellationToken.None);

        Assert.Equal("https://api.github.com/repos/nor0x/Alastor/releases/latest", http.LastUri?.ToString());
        Assert.Equal("v0.3.0", svc.Latest?.Tag);
        Assert.Equal("https://github.com/nor0x/Alastor/releases/tag/v0.3.0", svc.Latest?.Url); // built, not taken from html_url
        Assert.Equal(new DateTime(2026, 10, 20, 12, 0, 0, DateTimeKind.Utc), svc.Latest?.PublishedAt);
    }

    [Fact]
    public async Task Private_repository_or_no_release_means_no_update()
    {
        var svc = Create(new StubHandler(HttpStatusCode.NotFound, """{"message":"Not Found"}"""));
        await svc.CheckAsync(CancellationToken.None);
        Assert.Null(svc.Latest);
    }

    [Fact]
    public async Task Failures_keep_the_last_result()
    {
        var http = new StubHandler(HttpStatusCode.OK, """{"tag_name":"v0.3.0"}""");
        var svc = Create(http);
        await svc.CheckAsync(CancellationToken.None);

        http.Status = HttpStatusCode.InternalServerError;
        await svc.CheckAsync(CancellationToken.None);
        http.Status = HttpStatusCode.OK;
        http.Body = "not json";
        await svc.CheckAsync(CancellationToken.None);

        Assert.Equal("v0.3.0", svc.Latest?.Tag);
    }

    private static UpdateCheckService Create(StubHandler http) =>
        new(new StubFactory(http), Options.Create(new AlastorOptions()), TimeProvider.System, NullLogger<UpdateCheckService>.Instance);

    private sealed class StubFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class StubHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public HttpStatusCode Status { get; set; } = status;
        public string Body { get; set; } = body;
        public Uri? LastUri { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            LastUri = request.RequestUri;
            return Task.FromResult(new HttpResponseMessage(Status) { Content = new StringContent(Body, Encoding.UTF8, "application/json") });
        }
    }
}
