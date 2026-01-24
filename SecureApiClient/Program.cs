using System;
using System.IO;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Newtonsoft.Json;

// Secure API Client with mTLS + JWT
Console.WriteLine("Secure API Client - mTLS + JWT Demo");
Console.WriteLine("===================================");

// Base URL for the API
string baseUrl = "https://localhost:44336";

// Load certificates
var clientCert = LoadCertificateWithPrivateKey("certs/client.crt", "certs/client.key");
var caCert = new X509Certificate2("certs/ca.crt");

Console.WriteLine($"Loaded client certificate: {clientCert.Subject}");
Console.WriteLine($"Loaded CA certificate: {caCert.Subject}");

// Create HttpClient with mTLS configuration
var handler = new HttpClientHandler
{
    ClientCertificateOptions = ClientCertificateOption.Manual,
    SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
};

handler.ClientCertificates.Add(clientCert);

// Custom certificate validation
handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
{
    Console.WriteLine($"Server certificate validation: cert={cert?.Subject}, errors={errors}");

    // If no errors, accept
    if (errors == SslPolicyErrors.None)
        return true;

    // Add our CA to the chain for validation
    try
    {
        chain.ChainPolicy.ExtraStore.Add(caCert);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

        // Build the chain and validate
        bool chainResult = cert != null && chain.Build(cert);
        Console.WriteLine($"Chain validation result: {chainResult}");
        return chainResult;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Chain validation error: {ex.Message}");
        return false;
    }
};

using var httpClient = new HttpClient(handler);
httpClient.BaseAddress = new Uri(baseUrl);

// Test public endpoint (no auth required)
Console.WriteLine("\n1. Testing Public Endpoint (no auth)...");
try
{
    var response = await httpClient.GetAsync("/api/public/info");
    if (response.IsSuccessStatusCode)
    {
        var content = await response.Content.ReadAsStringAsync();
        Console.WriteLine("Public endpoint success:");
        Console.WriteLine(content);
    }
    else
    {
        Console.WriteLine($"Public endpoint failed: {response.StatusCode}");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Public endpoint error: {ex.Message}");
}

// Get JWT token
Console.WriteLine("\n2. Getting JWT Token...");
try
{
    var tokenResponse = await httpClient.PostAsync("/api/auth/login", null);
    if (tokenResponse.IsSuccessStatusCode)
    {
        var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
        var tokenData = JsonConvert.DeserializeObject<dynamic>(tokenContent);
        string jwtToken = tokenData?.token;

        Console.WriteLine($"JWT Token received: {jwtToken?.Substring(0, 50)}...");

        // Test secure endpoint with JWT token
        Console.WriteLine("\n3. Testing Secure Endpoint with JWT...");
        try
        {
            httpClient.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwtToken);

            var secureResponse = await httpClient.GetAsync("/api/secure/data");
            if (secureResponse.IsSuccessStatusCode)
            {
                var secureContent = await secureResponse.Content.ReadAsStringAsync();
                Console.WriteLine("Secure endpoint success:");
                Console.WriteLine(secureContent);
            }
            else
            {
                Console.WriteLine($"Secure endpoint failed: {secureResponse.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Secure endpoint error: {ex.Message}");
        }
    }
    else
    {
        Console.WriteLine($"Token request failed: {tokenResponse.StatusCode}");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Token request error: {ex.Message}");
}

Console.WriteLine("\nDemo completed. Press any key to exit.");
Console.ReadKey();

// Helper method to load certificate with private key
static X509Certificate2 LoadCertificateWithPrivateKey(string certPath, string keyPath)
{
    if (!File.Exists(certPath))
        throw new FileNotFoundException($"Certificate file not found: {certPath}", certPath);

    if (!File.Exists(keyPath))
        throw new FileNotFoundException($"Key file not found: {keyPath}", keyPath);

    // Try to create from PEM pair first
    var cert = X509Certificate2.CreateFromPemFile(certPath, keyPath);

    if (cert.HasPrivateKey)
        return cert;

    // If the returned cert doesn't have the private key attached, attach it manually.
    var keyPem = File.ReadAllText(keyPath);

    // PKCS#8 / RSA
    if (keyPem.Contains("BEGIN RSA") || keyPem.Contains("BEGIN PRIVATE KEY"))
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(keyPem.ToCharArray());
        return cert.CopyWithPrivateKey(rsa);
    }

    // EC
    if (keyPem.Contains("BEGIN EC") || keyPem.Contains("BEGIN EC PRIVATE KEY"))
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(keyPem.ToCharArray());
        return cert.CopyWithPrivateKey(ecdsa);
    }

    throw new InvalidOperationException("Unsupported or unrecognized key format.");
}
