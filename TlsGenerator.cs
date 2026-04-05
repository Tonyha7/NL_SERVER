using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NL_SERVER
{
    public static class TlsGenerator
    {
        public static X509Certificate2 EnsureSelfSignedCert(string certPath)
        {
            if (File.Exists(certPath))
            {
                return new X509Certificate2(certPath, "neverlose");
            }

            Console.WriteLine("Generating self-signed TLS certificate...");

            using var rsa = RSA.Create(2048);
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddIpAddress(IPAddress.Loopback);
            sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);

            var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(sanBuilder.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

            var cert = request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(10));
            
            var pfxBytes = cert.Export(X509ContentType.Pfx, "neverlose");

            var dir = Path.GetDirectoryName(certPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            File.WriteAllBytes(certPath, pfxBytes);
            
            Console.WriteLine($"Self-signed TLS cert written to {certPath}");
            
            return new X509Certificate2(certPath, "neverlose");
        }
    }
}