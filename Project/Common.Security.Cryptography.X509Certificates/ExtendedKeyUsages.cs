
namespace Common.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Specifies the extended usages of the public key of a certificate.
    /// </summary>
    public static class ExtendedKeyUsages
    {
        /// <summary>
        /// TLS/SSL server authentication.
        /// </summary>
        public static readonly string ServerAuthentication = "1.3.6.1.5.5.7.3.1";

        /// <summary>
        /// TLS/SSL client authentication.
        /// </summary>
        public static readonly string ClientAuthentication = "1.3.6.1.5.5.7.3.2";

        /// <summary>
        /// Signing of downloadable executable code.
        /// </summary>
        public static readonly string CodeSigning = "1.3.6.1.5.5.7.3.3";

        /// <summary>
        /// E-mail messages encryption.
        /// </summary>
        public static readonly string EmailProtection = "1.3.6.1.5.5.7.3.4";

        /// <summary>
        /// Binding the hash of an object to a time.
        /// </summary>
        public static readonly string TimeStamping = "1.3.6.1.5.5.7.3.8";

        /// <summary>
        /// Signing OCSP (Online Certificate Status Protocol) responses.
        /// </summary>
        public static readonly string OCSPSigning = "1.3.6.1.5.5.7.3.9";
    }
}
