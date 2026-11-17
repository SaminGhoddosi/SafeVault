using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using NUnit.Framework;

[TestFixture]
public class SecurityTests {
    private WebApplicationFactory<Program> factory = null!;
    private HttpClient client = null!;
    private string dbPath = null!;
    [SetUp] public void Setup() {
        dbPath = Path.Combine(Path.GetTempPath(), $"safevault-{Guid.NewGuid():N}.db");
        factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.ConfigureAppConfiguration((_, c) => c.AddInMemoryCollection(new Dictionary<string,string?> { ["DatabasePath"] = dbPath })));
        client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
    }
    [TearDown] public void Cleanup() { client.Dispose(); factory.Dispose(); if (File.Exists(dbPath)) File.Delete(dbPath); }
    [Test] public void SqlInjectionUsernameRejected() => Assert.That(InputRules.ValidUsername("admin' OR 1=1 --"), Is.False);
    [Test] public void XssUsernameRejected() => Assert.That(InputRules.ValidUsername("<script>alert(1)</script>"), Is.False);
    [Test] public void XssOutputEncoded() => Assert.That(InputRules.EncodeForHtml("<script>alert(1)</script>"), Does.Not.Contain("<script>"));
    [Test] public async Task SqlInjectionCannotLogin() {
        var response = await client.PostAsJsonAsync("/login", new { username = "admin' OR 1=1 --", password = "anything" });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }
    [Test] public async Task InvalidPasswordRejected() {
        await client.PostAsJsonAsync("/register", new { username = "alice", email = "alice@example.com", password = "correct-password-123" });
        var response = await client.PostAsJsonAsync("/login", new { username = "alice", password = "wrong-password" });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }
    [Test] public async Task NormalUserCannotAccessAdmin() {
        await client.PostAsJsonAsync("/register", new { username = "alice", email = "alice@example.com", password = "correct-password-123" });
        var login = await client.PostAsJsonAsync("/login", new { username = "alice", password = "correct-password-123" });
        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var response = await client.GetAsync("/admin");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }
    [Test] public async Task UnauthenticatedUserCannotAccessAdmin() {
        var response = await client.GetAsync("/admin");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
    }
    [Test] public async Task RegistrationRejectsScript() {
        var response = await client.PostAsJsonAsync("/register", new { username = "<script>", email = "a@example.com", password = "correct-password-123" });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }
}
