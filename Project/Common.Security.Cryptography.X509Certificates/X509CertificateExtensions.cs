using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace Common.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Extension methods for <see cref="X509Certificate"/>s.
    /// </summary>
    public static class X509CertificateExtensions
    {
        /// <summary>
        /// Checks if two certificates are the same.
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="other"></param>
        /// <returns></returns>
        /// <remarks>
        /// The built-in <see cref="X509Certificate.Equals"/> method only compares issuer and
        /// serial number which in theory are unique. However, this does not guarantee that the public/private key
        /// is the same expecially for self-signed certificates. This method uses both <see cref="X509Certificate.Equals"/>
        /// and the hash of the certificate to ensure they are the same.
        /// </remarks>
        public static bool IsEqualTo(this X509Certificate certificate, X509Certificate other)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate");
            }
            if (other == null)
            {
                throw new ArgumentNullException("other");
            }

            return certificate.Equals(other)
                && string.Equals(certificate.GetCertHashString(), other.GetCertHashString(), StringComparison.OrdinalIgnoreCase);
        }
    }
}
