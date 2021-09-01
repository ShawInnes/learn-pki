using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CreateCertSigningRequest
{
    class Program
    {
        static void Main(string[] args)
        {
            using (ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            using (ECDsa intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            using (ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                CertificateRequest rootRequest = new CertificateRequest(
                    "CN=Experimental Issuing Authority",
                    rootKey,
                    HashAlgorithmName.SHA256);

                rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));

                using (X509Certificate2 rootKeyAndCertificate = rootRequest.CreateSelfSigned(
                    DateTimeOffset.UtcNow.AddDays(-45),
                    DateTimeOffset.UtcNow.AddDays(3650)))
                {
                    CertificateRequest intermediateRequest = new CertificateRequest(
                        "CN=Experimental Intermediate Issuing Authority",
                        intermediateKey,
                        HashAlgorithmName.SHA256);

                    intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                    intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
                    intermediateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(intermediateRequest.PublicKey, false));
                    intermediateRequest.CertificateExtensions.Add(new X509AuthorityKeyIdentifierExtension(rootKeyAndCertificate, false));

                    var intermediateNotBefore = DateTimeOffset.UtcNow.AddDays(-1);
                    if (intermediateNotBefore < rootKeyAndCertificate.NotBefore)
                    {
                        intermediateNotBefore = new DateTimeOffset(rootKeyAndCertificate.NotBefore);
                    }

                    var intermediateNotAfter = DateTimeOffset.UtcNow.AddDays(90);
                    if (intermediateNotAfter > rootKeyAndCertificate.NotAfter)
                    {
                        intermediateNotAfter = new DateTimeOffset(rootKeyAndCertificate.NotAfter);
                    }

                    using (X509Certificate2 intermediateCertificate = intermediateRequest.Create(
                        rootKeyAndCertificate,
                        intermediateNotBefore,
                        intermediateNotAfter,
                        GetSerialNumber()))
                    {
                        CertificateRequest leafRequest = new CertificateRequest(
                            "CN=Experimental Leaf Node",
                            leafKey,
                            HashAlgorithmName.SHA256);

                        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
                        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                        leafRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(leafRequest.PublicKey, false));
                        leafRequest.CertificateExtensions.Add(new X509AuthorityKeyIdentifierExtension(intermediateCertificate, false));

                        var sanBuilder = new SubjectAlternativeNameBuilder();
                        // sanBuilder.AddEmailAddress("leaf@test.com");
                        sanBuilder.AddDnsName("www.test.com");
                        sanBuilder.AddDnsName("test.com");
                        var sanExtension = sanBuilder.Build();
                        leafRequest.CertificateExtensions.Add(sanExtension);

                        leafRequest.CertificateExtensions.Add(
                            new X509EnhancedKeyUsageExtension(
                                new OidCollection
                                {
                                    new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                                    new Oid("1.3.6.1.5.5.7.3.1") // TLS Server auth
                                },
                                false));

                        var leafNotBefore = DateTimeOffset.UtcNow.AddDays(-1);
                        if (leafNotBefore < intermediateCertificate.NotBefore)
                        {
                            leafNotBefore = new DateTimeOffset(intermediateCertificate.NotBefore);
                        }

                        var leafNotAfter = DateTimeOffset.UtcNow.AddDays(365);
                        if (leafNotAfter > intermediateCertificate.NotAfter)
                        {
                            leafNotAfter = new DateTimeOffset(intermediateCertificate.NotAfter);
                        }

                        var intermediateKeyAndCertificate = intermediateCertificate.CopyWithPrivateKey(intermediateKey);

                        using (X509Certificate2 leafCertificate = leafRequest.Create(
                            intermediateKeyAndCertificate,
                            leafNotBefore,
                            leafNotAfter,
                            GetSerialNumber()))
                        {
                            var leafKeyAndCertificate = leafCertificate.CopyWithPrivateKey(leafKey);

                            // File.WriteAllText("gen_root.crt", new string(PemEncoding.Write("CERTIFICATE", rootCertificate.RawData)));
                            // File.WriteAllText("gen_intermediate.crt", new string(PemEncoding.Write("CERTIFICATE", intermediateCertificate.RawData)));
                            // File.WriteAllText("gen_leaf.crt", new string(PemEncoding.Write("CERTIFICATE", leafCertificate.RawData)));

                            File.WriteAllBytes("gen_root.pfx", rootKeyAndCertificate.Export(X509ContentType.Pfx, "export"));
                            File.WriteAllBytes("gen_intermediate.pfx", intermediateKeyAndCertificate.Export(X509ContentType.Pfx, "export"));
                            File.WriteAllBytes("gen_leaf.pfx", leafKeyAndCertificate.Export(X509ContentType.Pfx, "export"));

                            // AsymmetricAlgorithm key = rootCertificate.GetECDsaPrivateKey();
                            // byte[] pubKeyBytes = key.ExportSubjectPublicKeyInfo();
                            // byte[] privKeyBytes = key.ExportPkcs8PrivateKey();
                            // char[] pubKeyPem = PemEncoding.Write("PUBLIC KEY", pubKeyBytes);
                            // // var pubKeyPemString = new string(pubKeyPem);
                            // Console.WriteLine(pubKeyPem);
                            // char[] privKeyPem = PemEncoding.Write("PRIVATE KEY", privKeyBytes);
                            // // var privKeyPemString = new string(privKeyPem);
                            // Console.WriteLine(privKeyPem);
                        }
                    }
                }
            }
        }

        private static byte[] GetSerialNumber()
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var unixTime = Convert.ToInt64((DateTime.UtcNow - epoch).TotalSeconds);
            var serialNumber = BitConverter.GetBytes(unixTime);
            return serialNumber;
        }

    }
}
