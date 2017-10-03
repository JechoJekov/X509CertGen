using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace Common.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Provides helper methods.
    /// </summary>
    public static class CertificateGenerationUtils
    {
        #region Issuer

        /// <summary>
        /// Checks if the specfied certificate is signed by the specified issuer certificate.
        /// </summary>
        /// <param name="certificate">The certificate to validate.</param>
        /// <param name="issuerCertificate">The certificate of the issuer.</param>
        /// <returns>
        /// 	<c>true</c> on success; <c>false</c> if the specified certificate is not signed by the
        /// specified issuer.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="certificate"/>
        /// or <paramref name="issuerCertificate"/> is <c>null</c>.</exception>
        public static bool ValidateCertificateIssuer(X509Certificate2 certificate, X509Certificate2 issuerCertificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate");
            }
            if (issuerCertificate == null)
            {
                throw new ArgumentNullException("issuerCertificate");
            }

            return ValidateCertificateIssuer(certificate, issuerCertificate.PublicKey);
        }

        /// <summary>
        /// Checks if the specfied certificate is signed by the specified public key.
        /// </summary>
        /// <param name="certificate">The certificate to validate.</param>
        /// <param name="issuerCertificate">The certificate of the issuer.</param>
        /// <returns>
        /// 	<c>true</c> on success; <c>false</c> if the specified certificate is not signed by the
        /// specified issuer.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="certificate"/>
        /// or <paramref name="issuerCertificate"/> is <c>null</c>.</exception>
        public static bool ValidateCertificateIssuer(X509Certificate2 certificate, PublicKey publicKey)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate");
            }
            if (publicKey == null)
            {
                throw new ArgumentNullException("publicKey");
            }

            var monoCertificate = new Mono.Security.X509.X509Certificate(certificate.GetRawCertData());

            return monoCertificate.VerifySignature(publicKey.Key);
        }

        #endregion
    }
}
