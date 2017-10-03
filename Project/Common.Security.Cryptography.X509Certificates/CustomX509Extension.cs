using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Mono.Security.X509;
using Mono.Security;

namespace Common.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Represents a custom X.509 extension that contains a binary value.
    /// </summary>
    public class CustomX509Extension : X509Extension
    {
        byte[] _extensionValue;

        /// <summary>
        /// Gets or sets the value of the extension.
        /// </summary>
        /// <value>The value of the extension.</value>
        /// <exception cref="ArgumentException"><paramref name="value"/> is more than 127 bytes.</exception>
        public byte[] ExtensionValue
        {
            get
            {
                return _extensionValue;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CustomX509Extension"/> class.
        /// </summary>
        /// <param name="oid">The OID of the extension.</param>
        /// <param name="extensionValue">The value of the extension.</param>
        /// <exception cref="ArgumentNullException"><paramref name="extensionValue"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException"><paramref name="extensionValue"/> is more than 127 bytes.</exception>
        public CustomX509Extension(string oid, byte[] extensionValue)
        {
            if (string.IsNullOrEmpty(oid))
            {
                throw new ArgumentNullException("oid");
            }

            if (extensionValue == null)
            {
                throw new ArgumentNullException("extensionValue");
            }

            if (extensionValue.Length > 127)
            {
                throw new ArgumentException("Must be up to 127 bytes long.", "extensionValue");
            }

            extnOid = oid;

            _extensionValue = extensionValue;
        }

        /// <summary>
        /// Encodes the value of the extension to ASN.1.
        /// </summary>
        protected override void Encode()
        {
            var asn1 = new ASN1(0x04);

            if (ExtensionValue != null)
            {
                asn1.Add(new ASN1(0x04, _extensionValue));
            }

            extnValue = asn1;
        }

        /// <summary>
        /// Decodes the value of the extension from ASN.1.
        /// </summary>
        protected override void Decode()
        {
            _extensionValue = new ASN1(extnValue.Value).Value;
        }
    }
}
