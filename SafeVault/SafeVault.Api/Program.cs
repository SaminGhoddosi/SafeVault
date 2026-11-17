using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options => { options.LoginPath = "/login"; options.Cookie.HttpOnly = true; options.Cookie.SecurePolicy = CookieSecurePolicy.Always; options.Cookie.SameSite = SameSiteMode.Strict; });
builder.Services.AddAuthorization();
builder.Services.AddAntiforgery();
var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();
var dbPath = builder.Configuration["DatabasePath"] ?? "safevault.db";
using (var db = new SqliteConnection($"Data Source={dbPath}")) {
    db.Open();
    using var cmd = db.CreateCommand();
    cmd.CommandText = "CREATE TABLE IF NOT EXISTS Users (UserID INTEGER PRIMARY KEY AUTOINCREMENT, Username TEXT NOT NULL UNIQUE, Email TEXT NOT NULL, PasswordHash TEXT NOT NULL, Role TEXT NOT NULL CHECK(Role IN ('admin','user')))";
    cmd.ExecuteNonQuery();
}
app.MapGet("/", () => Results.Content("SafeVault API is running", "text/plain"));
app.MapGet("/form", (Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgery, HttpContext ctx) => {
    var token = antiforgery.GetAndStoreTokens(ctx).RequestToken;
    return Results.Content($"<form method='post' action='/submit'><input name='__RequestVerificationToken' type='hidden' value='{WebUtility.HtmlEncode(token)}'/><input name='username' maxlength='100' required/><input name='email' type='email' maxlength='100' required/><button>Submit</button></form>", "text/html");
});
app.MapPost("/submit", (HttpContext ctx, [Microsoft.AspNetCore.Http.FromForm] string username, [Microsoft.AspNetCore.Http.FromForm] string email) => {
    if (!InputRules.ValidUsername(username) || !InputRules.ValidEmail(email)) return Results.BadRequest("Invalid input");
    return Results.Content($"<p>Username: {WebUtility.HtmlEncode(username)}</p><p>Email: {WebUtility.HtmlEncode(email)}</p>", "text/html");
});
app.MapPost("/register", (RegisterRequest request) => {
    if (!InputRules.ValidUsername(request.Username) || !InputRules.ValidEmail(request.Email) || request.Password is null || request.Password.Length < 12 || request.Password.Length > 128) return Results.BadRequest("Invalid registration");
    using var db = new SqliteConnection($"Data Source={dbPath}"); db.Open();
    using var cmd = db.CreateCommand();
    cmd.CommandText = "INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES ($name, $email, $hash, 'user')";
    cmd.Parameters.AddWithValue("$name", request.Username);
    cmd.Parameters.AddWithValue("$email", request.Email);
    cmd.Parameters.AddWithValue("$hash", BCrypt.Net.BCrypt.HashPassword(request.Password));
    try { cmd.ExecuteNonQuery(); return Results.Created("/users/me", new { request.Username }); }
    catch (SqliteException e) when (e.SqliteErrorCode == 19) { return Results.Conflict("Username already exists"); }
});
app.MapPost("/login", async (LoginRequest request, HttpContext ctx) => {
    using var db = new SqliteConnection($"Data Source={dbPath}"); db.Open();
    using var cmd = db.CreateCommand();
    cmd.CommandText = "SELECT UserID, PasswordHash, Role FROM Users WHERE Username = $name";
    cmd.Parameters.AddWithValue("$name", request.Username ?? "");
    using var reader = cmd.ExecuteReader();
    if (!reader.Read()) return Results.Unauthorized();
    var id = reader.GetInt64(0).ToString(); var hash = reader.GetString(1); var role = reader.GetString(2);
    if (request.Password is null || !BCrypt.Net.BCrypt.Verify(request.Password, hash)) return Results.Unauthorized();
    var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, id), new Claim(ClaimTypes.Name, request.Username!), new Claim(ClaimTypes.Role, role) }, CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
    return Results.Ok(new { message = "Logged in" });
});
app.MapGet("/users/me", (ClaimsPrincipal user) => Results.Ok(new { username = user.Identity!.Name })).RequireAuthorization();
app.MapGet("/admin", () => Results.Ok(new { message = "Admin dashboard" })).RequireAuthorization(policy => policy.RequireRole("admin"));
app.MapPost("/logout", async (HttpContext ctx) => { await ctx.SignOutAsync(); return Results.Ok(); }).RequireAuthorization();
app.Run();
public record RegisterRequest(string Username, string Email, string Password);
public record LoginRequest(string Username, string Password);
public static class InputRules {
    public static bool ValidUsername(string? s) => s is { Length: >= 3 and <= 100 } && s.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.');
    public static bool ValidEmail(string? s) => s is { Length: <= 100 and > 0 } && new EmailAddressAttribute().IsValid(s);
    public static string EncodeForHtml(string? s) => WebUtility.HtmlEncode(s ?? "");
}
public partial class Program { }
