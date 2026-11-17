# SafeVault (Activities 1, 2 and 3)
Simple ASP.NET Core 8 + SQLite + NUnit security example.

## Run
Requires .NET 8 SDK and internet access for NuGet restore.
```bash
dotnet run --project SafeVault.Api
```
Use the HTTPS URL printed by dotnet. Open `/form` for the CSRF-protected HTML form.

## Test
```bash
dotnet test SafeVault.Tests/SafeVault.Tests.csproj
```

## API
- `POST /register`: JSON `{ "username":"alice", "email":"alice@example.com", "password":"correct-password-123" }`
- `POST /login`: JSON `{ "username":"alice", "password":"correct-password-123" }` (sets auth cookie)
- `GET /users/me`: requires login
- `GET /admin`: requires admin role
- `POST /logout`: requires login

New users always receive the `user` role; there is no public admin registration. For an admin-role integration test, provision an admin account in a controlled test database. Never assign roles based on user-submitted registration fields.

## Security notes
SQL uses bound parameters. Passwords use bcrypt hashes. HTML output is encoded. Username is allowlisted; email is validated. Cookies are HttpOnly, Secure and SameSite=Strict. The browser form uses ASP.NET Core antiforgery tokens. API JSON POST routes are intended for API clients; if used cross-site with cookie authentication, add antiforgery protection or another CSRF defense. HTTPS is required for authentication cookies. Production deployment also needs rate limiting, logging, secret management and a secure admin provisioning process.

**Verification:** Tests are included but were NOT executed here because the .NET SDK is unavailable in the sandbox. Run `dotnet test` locally to verify.
