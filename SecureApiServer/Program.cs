using System.IO;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Server.Kestrel.Https;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Add JWT Authentication
var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.ASCII.GetBytes(jwtSettings["Secret"] ?? "your-secret-key-here-1234567890");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization();

// Configure mTLS
builder.WebHost.ConfigureKestrel(options =>
{
    // 🔓 Public HTTPS (no mTLS)
    options.ListenAnyIP(5000, listen =>
    {
        listen.UseHttps("certs/server.pfx", "123456");
    });
    options.ListenAnyIP(5001, listenOptions =>
    {
        listenOptions.UseHttps(https =>
        {
            // Load server certificate with private key
            var serverCert = X509Certificate2.CreateFromPemFile("certs/server.crt", "certs/server.key");
            https.ServerCertificate = serverCert;

            // Require client certificates
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;

            // Client certificate validation
            https.ClientCertificateValidation = (cert, chain, sslPolicyErrors) =>
            {
                if (cert == null)
                {
                    Console.WriteLine("No client certificate provided");
                    return false;
                }

                Console.WriteLine($"Client certificate received: {cert.Subject}");

                // Add CA certificate to chain for validation
                var caCert = X509Certificate2.CreateFromPemFile("certs/ca.crt");
                chain.ChainPolicy.ExtraStore.Add(caCert);

                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

                return chain.Build(cert);
            };
        });
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

// JWT Token generation endpoint
app.MapPost("/api/auth/login", [AllowAnonymous] () =>
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, "secure-api-user"),
            new Claim(ClaimTypes.Role, "api-user")
        }),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha256Signature)
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    var tokenString = tokenHandler.WriteToken(token);

    return Results.Ok(new { Token = tokenString });
});

// Secure endpoint requiring both mTLS and JWT
app.MapGet("/api/secure/data", [Authorize] (HttpContext context) =>
{
    var clientCert = context.Connection.ClientCertificate;
    var user = context.User.Identity?.Name;

    return Results.Ok(new
    {
        Message = "Secure data accessed successfully",
        User = user,
        ClientCertificate = clientCert?.Subject,
        Timestamp = DateTime.UtcNow,
        Data = new[] { "Item1", "Item2", "Item3" }
    });
});

// Public endpoint (no auth required)
app.MapGet("/api/public/info", [AllowAnonymous] () =>
{
    return Results.Ok(new
    {
        Message = "Public API information",
        ServerTime = DateTime.UtcNow,
        ApiVersion = "1.0"
    });
});

// Original weather endpoint
app.MapGet("/weatherforecast", () =>
{
    var forecast =  Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast");

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
