using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSignalR();
builder.Services.AddSingleton<IUserStore, InMemoryUserStore>();
builder.Services.AddSingleton<IPasswordProtector, Pbkdf2PasswordProtector>();
builder.Services.AddSingleton<IJwtTokenService, JwtTokenService>();

var jwtSection = builder.Configuration.GetSection("Jwt");
var jwtOptions = jwtSection.Get<JwtOptions>() ?? throw new InvalidOperationException("JWT settings are missing.");
if (string.IsNullOrWhiteSpace(jwtOptions.Key))
{
    throw new InvalidOperationException("JWT secret key is missing.");
}

builder.Services.AddSingleton(jwtOptions);

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Key)),
            ClockSkew = TimeSpan.Zero
        };

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var accessToken = context.Request.Query["access_token"];
                var path = context.HttpContext.Request.Path;
                if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/chatHub"))
                {
                    context.Token = accessToken;
                }

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/auth/register", async (RegisterRequest request, IUserStore userStore, IPasswordProtector passwordProtector) =>
{
    if (string.IsNullOrWhiteSpace(request.UserName) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest(new { message = "Логин и пароль обязательны." });
    }

    var exists = await userStore.ExistsAsync(request.UserName);
    if (exists)
    {
        return Results.Conflict(new { message = "Пользователь уже существует." });
    }

    var passwordHash = passwordProtector.HashPassword(request.Password);
    var user = new AppUser(request.UserName.Trim(), passwordHash);
    await userStore.AddAsync(user);

    return Results.Ok(new { message = "Пользователь зарегистрирован." });
});

app.MapPost("/api/auth/login", async (LoginRequest request, IUserStore userStore, IPasswordProtector passwordProtector, IJwtTokenService jwtTokenService) =>
{
    if (string.IsNullOrWhiteSpace(request.UserName) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest(new { message = "Логин и пароль обязательны." });
    }

    var user = await userStore.GetByUserNameAsync(request.UserName);
    if (user is null || !passwordProtector.VerifyPassword(request.Password, user.PasswordHash))
    {
        return Results.Unauthorized();
    }

    var token = jwtTokenService.GenerateToken(user.UserName);
    return Results.Ok(new LoginResponse(token));
});

app.MapHub<ChatHub>("/chatHub").RequireAuthorization();

app.Run();

record RegisterRequest(string UserName, string Password);
record LoginRequest(string UserName, string Password);
record LoginResponse(string AccessToken);
record AppUser(string UserName, string PasswordHash);

sealed class ChatHub : Hub
{
    [Authorize]
    public async Task SendMessage(string message)
    {
        var sender = Context.User?.Identity?.Name ?? "Unknown";
        await Clients.All.SendAsync("ReceiveMessage", sender, message, DateTime.Now.ToString("HH:mm:ss"));
    }
}

sealed class JwtOptions
{
    public string Issuer { get; init; } = string.Empty;
    public string Audience { get; init; } = string.Empty;
    public string Key { get; init; } = string.Empty;
    public int ExpiresMinutes { get; init; } = 60;
}

interface IJwtTokenService
{
    string GenerateToken(string userName);
}

sealed class JwtTokenService(JwtOptions options) : IJwtTokenService
{
    public string GenerateToken(string userName)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userName),
            new(ClaimTypes.Name, userName),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.Key));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.UtcNow.AddMinutes(options.ExpiresMinutes);

        var token = new JwtSecurityToken(
            issuer: options.Issuer,
            audience: options.Audience,
            claims: claims,
            expires: expires,
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

interface IUserStore
{
    Task<bool> ExistsAsync(string userName);
    Task AddAsync(AppUser user);
    Task<AppUser?> GetByUserNameAsync(string userName);
}

sealed class InMemoryUserStore : IUserStore
{
    private readonly ConcurrentDictionary<string, AppUser> _users = new(StringComparer.OrdinalIgnoreCase);

    public Task<bool> ExistsAsync(string userName) => Task.FromResult(_users.ContainsKey(userName.Trim()));

    public Task AddAsync(AppUser user)
    {
        _users[user.UserName] = user;
        return Task.CompletedTask;
    }

    public Task<AppUser?> GetByUserNameAsync(string userName)
    {
        _users.TryGetValue(userName.Trim(), out var user);
        return Task.FromResult(user);
    }
}

interface IPasswordProtector
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string passwordHash);
}

sealed class Pbkdf2PasswordProtector : IPasswordProtector
{
    private const int SaltSize = 16;
    private const int KeySize = 32;
    private const int Iterations = 100_000;

    public string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, KeySize);
        return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }

    public bool VerifyPassword(string password, string passwordHash)
    {
        var parts = passwordHash.Split(':');
        if (parts.Length != 2)
        {
            return false;
        }

        var salt = Convert.FromBase64String(parts[0]);
        var expectedHash = Convert.FromBase64String(parts[1]);
        var actualHash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, KeySize);

        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }
}
