using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

Console.WriteLine("Generating mTLS certificates for Secure API...");

// Create certs directory if it doesn't exist
string certsPath = Path.Combine(Directory.GetCurrentDirectory(), "certs");
Directory.CreateDirectory(certsPath);

// Generate CA certificate
Console.WriteLine("Generating CA certificate...");
GenerateCaCertificate(certsPath);

// Generate Server certificate
Console.WriteLine("Generating Server certificate...");
GenerateServerCertificate(certsPath);

// Generate Client certificate
Console.WriteLine("Generating Client certificate...");
GenerateClientCertificate(certsPath);

Console.WriteLine("Certificate generation complete!");

static void GenerateCaCertificate(string certsPath)
{
    using (RSA rsa = RSA.Create(4096))
    {
        var request = new CertificateRequest(
            "CN=SecureApiRootCA",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                true));

        var certificate = request.CreateSelfSigned(
            DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(365));

        // Export CA certificate and key
        File.WriteAllText(Path.Combine(certsPath, "ca.crt"),
            "-----BEGIN CERTIFICATE-----\r\n" +
            Convert.ToBase64String(certificate.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks) +
            "\r\n-----END CERTIFICATE-----");

        File.WriteAllText(Path.Combine(certsPath, "ca.key"),
            "-----BEGIN RSA PRIVATE KEY-----\r\n" +
            Convert.ToBase64String(rsa.ExportRSAPrivateKey(), Base64FormattingOptions.InsertLineBreaks) +
            "\r\n-----END RSA PRIVATE KEY-----");

        // Also save CA certificate with private key for signing
        File.WriteAllBytes(Path.Combine(certsPath, "ca.pfx"), certificate.Export(X509ContentType.Pfx, "password"));
    }
}

static void GenerateServerCertificate(string certsPath)
{
    using (RSA rsa = RSA.Create(4096))
    {
        var request = new CertificateRequest(
            "CN=localhost",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                false));

        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        // Load CA certificate with private key to sign the server certificate
        var caCertWithKey = new X509Certificate2(Path.Combine(certsPath, "ca.pfx"), "password");

        var certificate = request.Create(
            caCertWithKey,
            DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(364),
            new byte[] { 1, 2, 3, 4 });

        // Export server certificate and key
        File.WriteAllText(Path.Combine(certsPath, "server.crt"),
            "-----BEGIN CERTIFICATE-----\r\n" +
            Convert.ToBase64String(certificate.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks) +
            "\r\n-----END CERTIFICATE-----");

        File.WriteAllText(Path.Combine(certsPath, "server.key"),
            "-----BEGIN RSA PRIVATE KEY-----\r\n" +
            Convert.ToBase64String(rsa.ExportRSAPrivateKey(), Base64FormattingOptions.InsertLineBreaks) +
            "\r\n-----END RSA PRIVATE KEY-----");
    }
}

static void GenerateClientCertificate(string certsPath)
{
    using (RSA rsa = RSA.Create(4096))
    {
        var request = new CertificateRequest(
            "CN=secure-api-client",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                false));

        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        // Load CA certificate with private key to sign the client certificate
        var caCertWithKey = new X509Certificate2(Path.Combine(certsPath, "ca.pfx"), "password");

        var certificate = request.Create(
            caCertWithKey,
            DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(364),
            new byte[] { 1, 2, 3, 5 });

        // Export client certificate and key
        File.WriteAllText(Path.Combine(certsPath, "client.crt"),
            "-----BEGIN CERTIFICATE-----\r\n" +
            Convert.ToBase64String(certificate.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks) +
            "\r\n-----END CERTIFICATE-----");

        File.WriteAllText(Path.Combine(certsPath, "client.key"),
            "-----BEGIN RSA PRIVATE KEY-----\r\n" +
            Convert.ToBase64String(rsa.ExportRSAPrivateKey(), Base64FormattingOptions.InsertLineBreaks) +
            "\r\n-----END RSA PRIVATE KEY-----");
    }
}