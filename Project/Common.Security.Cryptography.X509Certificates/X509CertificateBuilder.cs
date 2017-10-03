#define MONO_BUG

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using Mono.Security.X509;
using Mono.Security;
using System.Security.Cryptography.X509Certificates;
using X509ExtensionCollection = Mono.Security.X509.X509ExtensionCollection;
using X509Extension = Mono.Security.X509.X509Extension;
using X509Certificate = Mono.Security.X509.X509Certificate;
using Mono.Security.X509.Extensions;
using System.Collections;
using System.Net;

namespace Common.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Provides the functionality to create a X.509 V3 certificate.
    /// </summary>
    public class X509CertificateBuilder
    {
        #region Properties

        #region Key usage

        /// <summary>
        /// Gets or sets the intended usages of the of the certificate.
        /// </summary>
        /// <value>The intended usages of the certificate.</value>
        public BasicKeyUsages KeyUsages { get; set; }

        bool _keyUsagesCritical = true;

        /// <summary>
        /// Gets or sets a value indicating whether the key usages of the certificate must be marked as critical.
        /// </summary>
        /// <value>
        /// 	<c>true</c> if the extended key-usages are critical; otherwise, <c>false</c>. The default is <c>true</c>.
        /// </value>
        public bool KeyUsagesCritical
        {
            get
            {
                return _keyUsagesCritical;
            }
            set
            {
                _keyUsagesCritical = value;
            }
        }

        /// <summary>
        /// Gets the list of extended key usages of the certificate.
        /// </summary>
        /// <value>A list containing the extended usages.</value>
        public IList<string> ExtendedKeyUsages { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the extended key usages of the certificate must be marked as critical.
        /// </summary>
        /// <value>
        /// 	<c>true</c> if the extended key-usages are critical; otherwise, <c>false</c>. The default is <c>false</c>.
        /// </value>
        /// <remarks>
        /// Marking the extended key usages as critical indicates that a party that validates or uses the certificate
        /// must respect them (e.g. if the certificate is used for server/client authentication and does not have the
        /// appropriate usages - it must be rejected).
        /// </remarks>
        public bool ExtendedKeyUsagesCritical { get; set; }

        #endregion

        #region Serial number

        byte[] _serialNumber;

        /// <summary>
        /// Gets or sets the serial number of the certificate.
        /// </summary>
        /// <value>The serial number of the certificate.</value>
        public byte[] SerialNumber
        {
            get
            {
                return _serialNumber == null ? null : (byte[])_serialNumber.Clone();
            }
            set
            {
                _serialNumber = value == null ? null : (byte[])value.Clone();
            }
        }

        #endregion

        #region Validity period

        /// <summary>
        /// Gets or sets the time after which the certificate is valid.
        /// </summary>
        /// <value>The time after which the certificate is valid.</value>
        public DateTime NotBefore
        {
            get
            {
                return _builder.NotBefore;
            }
            set
            {
                _builder.NotBefore = value;
            }
        }

        /// <summary>
        /// Gets or sets the time until which the certificate is valid.
        /// </summary>
        /// <value>The time until which the certificate is valid.</value>
        public DateTime NotAfter
        {
            get
            {
                return _builder.NotAfter;
            }
            set
            {
                _builder.NotAfter = value;
            }
        }

        #endregion

        #region Subject

        /// <summary>
        /// Gets or sets the subject name.
        /// </summary>
        /// <value>The subject name.</value>
        public string SubjectName
        {
            get
            {
                return _builder.SubjectName;
            }
            set
            {
                _builder.SubjectName = value;
            }
        }

        /// <summary>
        /// Gets or sets the subject alternative names (if any).
        /// </summary>
        public IList<string> SubjectAlternativeNames { get; set; }

        #endregion

        #region Public key

        /// <summary>
        /// Gets or sets the public key of the certificate.
        /// </summary>
        /// <value>The public key of the certificate.</value>
        public AsymmetricAlgorithm PublicKey
        {
            get
            {
                return _builder.SubjectPublicKey;
            }
            set
            {
                _builder.SubjectPublicKey = value;
            }
        }

        #endregion

        #region Extensions

        X509ExtensionCollection _extensions;

        /// <summary>
        /// Gets the list of additional extensions.
        /// </summary>
        /// <value>The list of additional extensions.</value>
        public X509ExtensionCollection Extensions
        {
            // The _builder.Extensions must NOT be returned directly by this property since this collection
            // can contain extensions created when the certificate is being signed (e.g. a "basic constraints" extension)
            // See the "PrepareSigning" method for more information

            get
            {
                if (_extensions == null)
                {
                    _extensions = new X509ExtensionCollection();
                }

                return _extensions;
            }
        }

        #endregion

        #region Certificate authority

        /// <summary>
        /// Gets or sets a value indicating whether the certificate is root or intermediate certificate authority (CA).
        /// </summary>
        /// <value>
        /// 	<c>true</c> if this instance is a certificate authority; otherwise, <c>false</c>.
        /// </value>
        public bool IsCertificateAuthority { get; set; }

        int _certificateAuthorityPathLength = -1;

        /// <summary>
        /// Gets or sets the maximum number of intermediate CA certificates that may follow this certificate
        /// until an end-user certificate.
        /// </summary>
        /// <value>
        /// The maximum number of intermediate CA certificates. The default is -1 (unlimited).
        /// </value>
        /// <exception cref="ArgumentOutOfRangeException">The setter is called and the value is less than -1.</exception>
        public int CertificateAuthorityPathLength
        {
            get
            {
                return _certificateAuthorityPathLength;
            }
            set
            {
                if (value < -1)
                {
                    throw new ArgumentOutOfRangeException("value", value, "Must be greater than or equal to -1.");
                }

                _certificateAuthorityPathLength = value;
            }
        }

        #endregion

        #endregion

        #region Fields

        /// <summary>
        /// The underlying certificate builder provided by in Mono.
        /// </summary>
        Mono.Security.X509.X509CertificateBuilder _builder;

        /// <summary>
        /// The signed certificate.
        /// </summary>
        byte[] _signedCertificate;

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the <see cref="X509CertificateBuilder"/> class.
        /// </summary>
        public X509CertificateBuilder()
        {
            _builder = new Mono.Security.X509.X509CertificateBuilder(3);
        }

        #endregion

        #region Public methods

        #region Signing

        /// <summary>
        /// Signs the certificate with the certificate of an issuer.
        /// </summary>
        /// <param name="issuerCertificate">The certificate of the issuer.</param>
        /// <exception cref="ArgumentNullException"><paramref name="issuerCertificate"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException"><paramref name="issuerCertificate"/> does not have a private key.</exception>
        /// <exception cref="ArgumentException"><paramref name="issuerCertificate"/> is not a CA.</exception>
        public void Sign(X509Certificate2 issuerCertificate)
        {
            if (issuerCertificate == null)
            {
                throw new ArgumentNullException("issuerCertificate");
            }

            if (false == issuerCertificate.HasPrivateKey)
            {
                throw new ArgumentException("The certificate must have a private key.", "issuerCertificate");
            }

            // Throws System.Security.Cryptography.CryptographicException: Invalid algorithm specified.
            // The probable reason is perhaps the way the key is loaded.
            // One way to avoid this error is to export the key and import it to a new RSA instance
            /*
            Sign(issuerCertificate, (RSACryptoServiceProvider)issuerCertificate.PrivateKey);
            */

            using (var rsa = new RSACryptoServiceProvider(new CspParameters() { Flags = CspProviderFlags.UseDefaultKeyContainer | CspProviderFlags.CreateEphemeralKey }))
            {
                try
                {
                    rsa.ImportCspBlob(((RSACryptoServiceProvider)issuerCertificate.PrivateKey).ExportCspBlob(true));

                    Sign(issuerCertificate, rsa);
                }
                finally
                {
                    // Remove the key from the key container. Otherwise, the key will be kept on the file
                    // system which is completely undesirable.
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        /// <summary>
        /// Signs the certificate with the certificate of an issuer.
        /// </summary>
        /// <param name="issuerCertificate">The certificate of the issuer.</param>
        /// <param name="privateKey">The private key of the issuer.</param>
        /// <exception cref="ArgumentNullException"><paramref name="issuerCertificate"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="privateKey"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException"><paramref name="issuerCertificate"/> is not a CA.</exception>
        public void Sign(X509Certificate2 issuerCertificate, AsymmetricAlgorithm privateKey)
        {
            if (issuerCertificate == null)
            {
                throw new ArgumentNullException("issuerCertificate");
            }

            if (privateKey == null)
            {
                throw new ArgumentNullException("privateKey");
            }

            var basicConstraintsExtension = issuerCertificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();

            if (basicConstraintsExtension == null || false == basicConstraintsExtension.CertificateAuthority)
            {
                throw new ArgumentException("The certificate must be a CA.", "issuerCertificate");
            }

            var monoIssuerCertificate = new X509Certificate(issuerCertificate.GetRawCertData());

            PrepareSigning();

            _builder.IssuerName = monoIssuerCertificate.SubjectName;

            // Get the subject key identifier of the issuer's certificate. This identifier can be used when a X.509 certificate
            // chain is build to validate an end-user certificate.
            var subjectKeyIdentifier = GetSubjectKeyIdentififer(monoIssuerCertificate);

            if (subjectKeyIdentifier != null)
            {
                // Add an "authority key identifier" extension to the new certificate. The extension contains
                // the "subject key identifier" of the issuer's certificate and is used to identify it when
                // a X.509 certificate verification chain is build
                _builder.Extensions.Add(CreateAuthorityKeyIdentifier(subjectKeyIdentifier));
            }

            if (IsCertificateAuthority)
            {
                // Create a subject key by which the certificate can be identified when a X.509 certificate chain is build
                // This is required since the certificate will be used to validate other certificates
                var extension = CreateSubjectKeyIdentifier(Guid.NewGuid().ToByteArray());

                _builder.Extensions.Add(extension);
            }

            _signedCertificate = _builder.Sign(privateKey);
        }

        /// <summary>
        /// Self-signs the certificate.
        /// </summary>
        /// <param name="privateKey">The private key corresponding to the public key of the certificate (since
        /// the certificate is self-signing).</param>
        /// <exception cref="ArgumentNullException"><paramref name="privateKey"/> is <c>null</c>.</exception>
        public void SelfSign(AsymmetricAlgorithm privateKey)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException("privateKey");
            }

            PrepareSigning();

            if (IsCertificateAuthority)
            {
                // Create a subject key by which the certificate can be identified when a X.509 certificate chain is build
                // This is required since the certificate will be used to validate other certificates
                var extension = CreateSubjectKeyIdentifier(Guid.NewGuid().ToByteArray());

                _builder.Extensions.Add(extension);
            }

            _builder.IssuerName = _builder.SubjectName;

            _signedCertificate = _builder.Sign(privateKey);
        }

        #endregion

        #region Export

        /// <summary>
        /// Exports the X.509 certificate in CERT (.cer) format.
        /// </summary>
        /// <returns>The certificate.</returns>
        /// <exception cref="InvalidOperationException">The certificate is not signed.</exception>
        /// <remarks>You must call the <see cref="SelfSign"/> of <see cref="Sign"/> method before
        /// exporting the certificate.</remarks>
        public byte[] Export()
        {
            if (_signedCertificate == null)
            {
                throw new InvalidOperationException("The certificate is not signed.");
            }

            return (byte[])_signedCertificate.Clone();
        }

        /// <summary>
        /// Exports the X.509 certificate and its private key in PKCS#12 (.pfx, .p12) format.
        /// </summary>
        /// <param name="privateKey">The certificate's private key.</param>
        /// <param name="password">The password to use to protect the private key.</param>
        /// <param name="iterations">The iterations to perform to derive encryption keys from the password.</param>
        /// <returns>The certificate.</returns>
        /// <exception cref="InvalidOperationException">The certificate is not signed.</exception>
        /// <remarks>You must call the <see cref="SelfSign"/> of <see cref="Sign"/> method before
        /// exporting the certificate.</remarks>
        public byte[] ExportPkcs12(AsymmetricAlgorithm privateKey, string password)
        {
            return ExportPkcs12(privateKey, password, 10000);
        }

        /// <summary>
        /// Exports the X.509 certificate and its private key in PKCS#12 (.pfx, .p12) format.
        /// </summary>
        /// <param name="privateKey">The certificate's private key.</param>
        /// <param name="password">The password to use to protect the private key.</param>
        /// <param name="iterations">The iterations to perform to derive encryption keys from the password.</param>
        /// <returns>The certificate.</returns>
        /// <exception cref="InvalidOperationException">The certificate is not signed.</exception>
        /// <remarks>You must call the <see cref="SelfSign"/> of <see cref="Sign"/> method before
        /// exporting the certificate.</remarks>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is less than 1000.</exception>
        /// <exception cref="ArgumentException"><paramref name="privateKey"/> is not exportable.</exception>
        public byte[] ExportPkcs12(AsymmetricAlgorithm privateKey, string password, int iterations)
        {
            if (_signedCertificate == null)
            {
                throw new InvalidOperationException("The certificate is not signed.");
            }

            if (privateKey == null)
            {
                throw new ArgumentNullException("privateKey");
            }

            if (iterations < 1000)
            {
                throw new ArgumentOutOfRangeException("iterations", iterations, "Must be greater than or equal to 1000.");
            }

            if (privateKey is ICspAsymmetricAlgorithm)
            {
                var container = ((ICspAsymmetricAlgorithm)privateKey).CspKeyContainerInfo;

                if (container.KeyContainerName == null || container.Exportable)
                {
                    // The container is valid
                }
                else
                {
                    throw new ArgumentException("The private key must be exportable.", "privateKey");
                }
            }

            PKCS12 p12 = new PKCS12();

            p12.IterationCount = iterations;

            p12.Password = password ?? string.Empty;

            ArrayList list = new ArrayList();

            // We use a fixed array to avoid endianess issues 
            // (in case some tools requires the ID to be 1).
            list.Add(new byte[4] { 1, 0, 0, 0 });

            var attributes = new Hashtable(1);

            attributes.Add(PKCS9.localKeyId, list);

            p12.AddCertificate(
                new X509Certificate(_signedCertificate),
                attributes
                );

            p12.AddPkcs8ShroudedKeyBag(privateKey, attributes);

            return p12.GetBytes();
        }

        #endregion

        #endregion

        #region Private methods

        /// <summary>
        /// Applies the basic constrains and key usages to the underlying certificate builder
        /// before the certificate is signed.
        /// </summary>
        void PrepareSigning()
        {
            // Set the signing hashing function
            _builder.Hash = "SHA256";

            // Clear all extensions created during the previous preparation
            _builder.Extensions.Clear();

            #region Subject

            if (SubjectAlternativeNames != null && SubjectAlternativeNames.Count > 0)
            {
                var dnsNameList = new List<string>();
                var ipList = new List<string>();

                foreach (var item in SubjectAlternativeNames)
                {
                    IPAddress ipAddress;
                    if (IPAddress.TryParse(item, out ipAddress))
                    {
                        ipList.Add(item);
                    }
                    else
                    {
                        dnsNameList.Add(item);
                    }
                }

                var extension = new SubjectAltNameExtension(null, dnsNameList.ToArray(), ipList.ToArray(), null);
                _builder.Extensions.Add(extension);
            }

            #endregion

            #region Serial number

            {
                var serialNumber = _serialNumber == null ? null : (byte[])_serialNumber.Clone();

                if (serialNumber == null)
                {
                    serialNumber = Guid.NewGuid().ToByteArray();
                }

                /* // The serial number is correctly set and must NOT be reversed
                // Convert the serial number to big endian format
                Array.Reverse(serialNumber);
                */

                _builder.SerialNumber = serialNumber;
            }

            #endregion

            #region Basic key usages

            var keyUsages = KeyUsages;

            if (IsCertificateAuthority)
            {
                // Indicate that the public key of the certificate can be used to validate the signatures of
                // other certificates
                keyUsages |= BasicKeyUsages.KeyCertSign;

                var extension = new BasicConstraintsExtension()
                    {
                        CertificateAuthority = true,
                        PathLenConstraint = CertificateAuthorityPathLength,
                        // This extension must be critical
                        Critical = true,
                    };

                _builder.Extensions.Add(extension);
            }
            else
            {
                keyUsages &= ~BasicKeyUsages.KeyCertSign;
            }

            if (keyUsages != BasicKeyUsages.None)
            {
#if MONO_BUG
                // There was a bug in the Mono implementation of the KeyUsageExtension
                // which is still NOT fixed
                var buffer = new System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
                    (System.Security.Cryptography.X509Certificates.X509KeyUsageFlags)keyUsages,
                    false
                    ).RawData;

                var asn = new ASN1(0x30, buffer);

                asn.Add(ASN1Convert.FromOid("2.5.29.15"));

                asn.Add(new ASN1(4, buffer));

                _builder.Extensions.Add(new X509Extension(asn) {  Critical = KeyUsagesCritical });
#else
                // This code should be used once the bug is fixed
                var extension = new KeyUsageExtension()
                    {
                        KeyUsage = (KeyUsages)keyUsages,
                        Critical = KeyUsagesCritical,
                    };

                _builder.Extensions.Add(extension);
#endif
            }

            #endregion

            #region Extended key usage

            if (ExtendedKeyUsages != null && ExtendedKeyUsages.Count > 0)
            {
                var extension = new ExtendedKeyUsageExtension();

                extension.Critical = ExtendedKeyUsagesCritical;

                foreach (var item in ExtendedKeyUsages)
                {
                    // Avoid dupliated key usages
                    if (false == extension.KeyPurpose.Contains(item))
                    {
                        extension.KeyPurpose.Add(item);
                    }
                }

                _builder.Extensions.Add(extension);
            }

#endregion

#region Custom extensions

            if (_extensions != null)
            {
                _builder.Extensions.AddRange(_extensions);
            }

#endregion
        }

#endregion

#region Static helper methods

#region ASN.1

        /// <summary>
        /// Decodes DER encoded an ASN.1 octet string.
        /// </summary>
        /// <param name="buffer">The buffer containing the string.</param>
        /// <returns>The decoded string.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="buffer"/> is <c>null</c>.</exception>
        static byte[] DecodeOctetString(byte[] buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }

            if (buffer.Length == 0)
            {
                throw new ArgumentException("Must be at least one bytes long.", "buffer");
            }

            var length = buffer[0];

            if (length + 1 != buffer.Length)
            {
                throw new FormatException("Not a valid octet string.");
            }

            var result = new byte[length];

            Buffer.BlockCopy(buffer, 1, result, 0, length);

            return result;
        }

        /// <summary>
        /// Encodes an ASN.1 octet string in DER format.
        /// </summary>
        /// <param name="buffer">The value of the string.</param>
        /// <returns>The encoded string.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="buffer"/> is <c>null</c>.</exception>
        static byte[] EncodeOctetString(byte[] buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }

            var result = new byte[buffer.Length + 1];

            result[0] = (byte)buffer.Length;

            Buffer.BlockCopy(buffer, 0, result, 1, buffer.Length);

            return result;
        }

#endregion

#region Key identifier

        /// <summary>
        /// Returns the subject key identifier of a certificate.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <returns>
        /// The subject key identifier of a certificate of <c>null</c> if the certificate
        /// does not have a subject key identifier.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is <c>null</c>.</exception>
        static byte[] GetSubjectKeyIdentififer(X509Certificate certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate");
            }

            foreach (X509Extension item in certificate.Extensions)
            {
                if (item.Oid == "2.5.29.14")
                {
                    var value = item.Value;

                    if (value == null || value.Tag != 4)
                    {
                        throw new FormatException("Invalid subject key identifier.");
                    }

                    value = item.Value;

                    if (value == null || value.Tag != 4)
                    {
                        throw new FormatException("Invalid subject key identifier.");
                    }

                    value = new ASN1(value.Value);

                    if (value == null || value.Tag != 4)
                    {
                        throw new FormatException("Invalid subject key identifier.");
                    }

                    return value.Value;
                }
            }

            return null;
        }

        /// <summary>
        /// Creates a subject key identifier extension.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier.</param>
        /// <returns>
        /// A subject key identifier extension that contains the key identifier.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="keyIdentifier"/> is <c>null</c>.</exception>
        static X509Extension CreateSubjectKeyIdentifier(byte[] keyIdentifier)
        {
            if (keyIdentifier == null)
            {
                throw new ArgumentNullException("keyIdentifier");
            }

            var asn = new ASN1(0x30);

            asn.Add(ASN1Convert.FromOid("2.5.29.14"));

            asn.Add(new ASN1(4, new ASN1(4, keyIdentifier).GetBytes()));

            return new X509Extension(asn);
        }

        /// <summary>
        /// Creates a authority key identifier extension.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier.</param>
        /// <returns>
        /// A authority key identifier extension that contains the key identifier.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="keyIdentifier"/> is <c>null</c>.</exception>
        static X509Extension CreateAuthorityKeyIdentifier(byte[] keyIdentifier)
        {
            if (keyIdentifier == null)
            {
                throw new ArgumentNullException("keyIdentifier");
            }

            var asn = new ASN1(0x30);

            asn.Add(ASN1Convert.FromOid("2.5.29.35"));

            var binaryKeyIdentifier = EncodeOctetString(keyIdentifier);

            var buffer = new byte[binaryKeyIdentifier.Length + 1];

            buffer[0] = 0x80;

            Buffer.BlockCopy(
                binaryKeyIdentifier,
                0,
                buffer,
                1,
                binaryKeyIdentifier.Length
                );

            asn.Add(new ASN1(4, new ASN1(0x30, buffer).GetBytes()));

            return new X509Extension(asn);
        }

#endregion

#endregion
    }
}
