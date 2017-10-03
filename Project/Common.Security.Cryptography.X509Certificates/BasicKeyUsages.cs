using System;

namespace Common.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Specifies the basic usages a certificate.
    /// </summary>
    [Flags]
    public enum BasicKeyUsages
    {
        /// <summary>
        /// The subject public key is used for verifying digital signatures
        /// other than signatures on certificates and CRLs such as those used in an 
        /// entity authentication service, a data origin authentication
        /// service, and/or an integrity service.
        /// </summary>
        DigitalSignature = 0x80,
        /// <summary>
        /// The subject public key is used to verify digital signatures, other than
        /// signatures on
        /// certificates and CRLs, used to provide a 
        /// non-repudiation service that protects against the signing entity falsely
        /// denying some action.
        /// </summary>
        NonRepudiation = 0x40,
        /// <summary>
        /// The subject public key is used for enciphering private or secret keys,
        /// i.e., for key transport.
        /// </summary>
        KeyEncipherment = 0x20,
        /// <summary>
        /// The subject public key is used for directly enciphering raw user
        /// data without the use of an intermediate symmetric cipher.
        /// </summary>
        DataEncipherment = 0x10,
        /// <summary>
        /// The subject public key is used for key agreement.
        /// </summary>
        KeyAgreement = 0x08,
        /// <summary>
        /// The subject public key is used for verifying signatures on public 
        /// key certificates.
        /// </summary>
        KeyCertSign = 0x04,
        /// <summary>
        /// The subject public key is used for verifying signatures on certificate
        /// revocation lists.
        /// </summary>
        CRLSign = 0x02,
        /// <summary>
        /// When the <see cref="KeyAgreement"/>
        /// flag is also specified, the subject public key may be used only for enciphering 
        /// data while performing key agreement.
        /// </summary>
        EncipherOnly = 0x01,
        /// <summary>
        /// When the <see cref="KeyAgreement"/>
        /// flag is also specified, the subject public key may be used only for deciphering 
        /// data while performing key agreement.
        /// </summary>
        DecipherOnly = 0x800,
        /// <summary>
        /// Not specified.
        /// </summary>
        None = 0x0
    }
}
