using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Common.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Represents an attribute of a X.501 distinguished name.
    /// </summary>
    public class X501DistinguishedNameAttribute
    {
        /// <summary>
        /// Gets the type of the attribute.
        /// </summary>
        /// <value>The type of the attribute.</value>
        public string Type { get; private set; }

        /// <summary>
        /// Gets the value of the attribute.
        /// </summary>
        /// <value>The value of the attribute.</value>
        public object Value { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="X501DistinguishedNameEntry"/> class.
        /// </summary>
        /// <param name="type">The type of the attribute.</param>
        /// <param name="value">The value of the attribute.</param>
        /// <exception cref="ArgumentNullException"><paramref name="type"/> is <c>null</c> or empty.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="value"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="value"/> is an empty <see cref="String"/>.</exception>
        /// <exception cref="ArgumentException"><paramref name="value"/> is an empty <see cref="Array"/> of <see cref="Byte"/>.</exception>
        /// <exception cref="ArgumentException"><paramref name="value"/> is neither string neither an array of bytes.</exception>
        public X501DistinguishedNameAttribute(string type, object value)
        {
            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentNullException("type");
            }

            if (value == null)
            {
                throw new ArgumentNullException("value");
            }

            if (value is string)
            {
                if (((string)value).Length == 0)
                {
                    throw new ArgumentNullException("value");
                }
            }
            else if (value is byte[])
            {
                if (((byte[])value).Length == 0)
                {
                    throw new ArgumentException("Must contain at least one element.", "value");
                }
            }
            else
            {
                throw new ArgumentException("Must be a string or an array of bytes.", "value");
            }

            Type = type;

            Value = value;
        }
    }
}
