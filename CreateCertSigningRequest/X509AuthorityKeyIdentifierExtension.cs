using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CreateCertSigningRequest
{
    public class X509AuthorityKeyIdentifierExtension : X509Extension
    {
        private static Oid AuthorityKeyIdentifierOid => new Oid("2.5.29.35");
        private static Oid SubjectKeyIdentifierOid => new Oid("2.5.29.14");

        public X509AuthorityKeyIdentifierExtension(X509Certificate2 certificateAuthority, bool critical)
            : base(AuthorityKeyIdentifierOid, EncodeExtension(certificateAuthority), critical)
        {
        }

        private static byte[] EncodeExtension(X509Certificate2 certificateAuthority)
        {
            var subjectKeyIdentifier= certificateAuthority.Extensions.Cast<X509Extension>().FirstOrDefault(p => p.Oid?.Value == SubjectKeyIdentifierOid.Value);
            if (subjectKeyIdentifier == null)
                return null;
            var rawData = subjectKeyIdentifier.RawData;
            var segment = new ArraySegment<byte>(rawData, 2, rawData.Length - 2);
            var authorityKeyIdentifier = new byte[segment.Count + 4];
            // KeyID of the AuthorityKeyIdentifier
            authorityKeyIdentifier[0] = 0x30;
            authorityKeyIdentifier[1] = 0x16;
            authorityKeyIdentifier[2] = 0x80;
            authorityKeyIdentifier[3] = 0x14;
            segment.CopyTo(authorityKeyIdentifier, 4);
            return authorityKeyIdentifier;
        }
    }
}
