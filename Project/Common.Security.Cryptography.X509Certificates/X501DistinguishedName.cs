using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;

namespace Common.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Represents a X.501 distinguished name.
    /// </summary>
    public class X501DistinguishedName
    {
        #region Constants

        /// <summary>
        /// The list of characters that must be escaped if contained in an attribute's value.
        /// </summary>
        readonly static char[] SpecialCharacters = { ',', '+', '\'', '\\', '<', '>', ';', '#', '"' };

        #endregion

        #region Properties

        List<X501DistinguishedNameAttribute> _attributes;

        /// <summary>
        /// Gets a collection containing the custom attributes of the name.
        /// </summary>
        /// <value>A collection containing the custom attributes of the name.</value>
        public List<X501DistinguishedNameAttribute> CustomAttributes
        {
            get
            {
                if (_attributes == null)
                {
                    _attributes = new List<X501DistinguishedNameAttribute>();
                }

                return _attributes;
            }
        }

        public string CommonName { get; set; }

        public string Locality { get; set; }

        public string StateOrProvince { get; set; }

        public string Organization { get; set; }

        public string OrganizationalUnit { get; set; }

        public string Country { get; set; }

        public string StreetAddress { get; set; }

        public string DomainComponent { get; set; }

        public string UserID { get; set; }

        public string Email { get; set; }

        public string Title { get; set; }

        public string GivenName { get; set; }

        public string Surname { get; set; }

        public string Initial { get; set; }

        public string DistinguishedNameQualifier { get; set; }

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the <see cref="X501DistinguishedName"/> class.
        /// </summary>
        public X501DistinguishedName() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="X501DistinguishedName"/> class.
        /// </summary>
        /// <param name="commonName">The common name.</param>
        public X501DistinguishedName(string commonName)
        {
            CommonName = commonName;
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Returns the string representation of the distinguised name.
        /// </summary>
        /// <returns>
        /// A <see cref='System.String'/> that represents the distinguished name.
        /// </returns>
        public override string ToString()
        {
            var sb = new StringBuilder(100);

            if (false == string.IsNullOrEmpty(CommonName))
            {
                AddAttribute(sb, "CN", CommonName);
            }

            if (false == string.IsNullOrEmpty(Locality))
            {
                AddAttribute(sb, "L", Locality);
            }

            if (false == string.IsNullOrEmpty(StateOrProvince))
            {
                AddAttribute(sb, "ST", StateOrProvince);
            }

            if (false == string.IsNullOrEmpty(Organization))
            {
                AddAttribute(sb, "O", Organization);
            }

            if (false == string.IsNullOrEmpty(OrganizationalUnit))
            {
                AddAttribute(sb, "OU", OrganizationalUnit);
            }

            if (false == string.IsNullOrEmpty(Country))
            {
                AddAttribute(sb, "C", Country);
            }

            if (false == string.IsNullOrEmpty(StreetAddress))
            {
                AddAttribute(sb, "STREET", StreetAddress);
            }

            if (false == string.IsNullOrEmpty(DomainComponent))
            {
                AddAttribute(sb, "DC", DomainComponent);
            }

            if (false == string.IsNullOrEmpty(UserID))
            {
                AddAttribute(sb, "UID", UserID);
            }

            if (false == string.IsNullOrEmpty(Email))
            {
                AddAttribute(sb, "E", Email);
            }

            if (false == string.IsNullOrEmpty(Title))
            {
                AddAttribute(sb, "T", Title);
            }

            if (false == string.IsNullOrEmpty(GivenName))
            {
                AddAttribute(sb, "G", GivenName);
            }

            if (false == string.IsNullOrEmpty(Surname))
            {
                AddAttribute(sb, "SN", Surname);
            }

            if (false == string.IsNullOrEmpty(Initial))
            {
                AddAttribute(sb, "I", Initial);
            }

            if (false == string.IsNullOrEmpty(DistinguishedNameQualifier))
            {
                AddAttribute(sb, "DNQUALIFIER", DistinguishedNameQualifier);
            }

            if (_attributes != null)
            {
                foreach (var item in _attributes)
                {
                    AddAttribute(sb, item.Type, item.Value);
                }
            }

            return sb.ToString();
        }

        #endregion

        #region Public static methods

        /// <summary>
        /// Parses a distinguished name represented as a <see cref="String"/>.
        /// </summary>
        /// <param name="value">The value to parse.</param>
        /// <returns>
        /// The resulting <see cref="X501DistinguishedName"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="value"/> is <c>null</c> or empty.</exception>
        /// <exception cref="FormatException">The value is invalid.</exception>
        public static X501DistinguishedName Parse(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentNullException("value");
            }

            var match = RdnSequence.Regex.Match(value);

            if (match == null || match == Match.Empty)
            {
                // No match was found

                throw new FormatException("The value is not a valid distinguished name.");
            }

            var result = new X501DistinguishedName();

            var attributes = match.Groups["attribute"].Captures;

            var values = match.Groups["value"].Captures;

            for (var i = 0; i < attributes.Count; i++)
            {
                var attributeType = attributes[i].Value.ToUpper();

                var attributeValue = values[i].Value;

                var unescapedValue = RdnSequence.UnescapeValue(attributeValue);

                var unescapedValueString = unescapedValue as string;

                if (unescapedValueString == null)
                {
                    // The value is a hexadecimal byte array
                    result.CustomAttributes.Add(new X501DistinguishedNameAttribute(attributeType, unescapedValue));

                    continue;
                }

                switch (attributeType)
                {
                    case "CN":
                        result.CommonName = unescapedValueString;
                        break;
                    case "O":
                        result.Organization = unescapedValueString;
                        break;
                    case "OU":
                        result.OrganizationalUnit = unescapedValueString;
                        break;
                    case "L":
                        result.Locality = unescapedValueString;
                        break;
                    case "C":
                        result.Country = unescapedValueString;
                        break;
                    case "ST":
                        result.StateOrProvince = unescapedValueString;
                        break;
                    case "STREET":
                        result.StreetAddress = unescapedValueString;
                        break;
                    case "DC":
                        result.DomainComponent = unescapedValueString;
                        break;
                    case "UID":
                        result.UserID = unescapedValueString;
                        break;
                    case "E":
                        result.Email = unescapedValueString;
                        break;
                    case "T":
                        result.Title = unescapedValueString;
                        break;
                    case "G":
                        result.GivenName = unescapedValueString;
                        break;
                    case "SN":
                        result.Surname = unescapedValueString;
                        break;
                    case "I":
                        result.Initial = unescapedValueString;
                        break;
                    case "DNQUALIFIER":
                        result.DistinguishedNameQualifier = unescapedValueString;
                        break;
                    default:
                        result.CustomAttributes.Add(new X501DistinguishedNameAttribute(attributeType, unescapedValueString));
                        break;
                }
            }

            return result;
        }

        #endregion

        #region Private methods

        /// <summary>
        /// Adds an attribute to the name.
        /// </summary>
        /// <param name="sb">The <see cref="StringBuilder"/> containing the name.</param>
        /// <param name="type">The type of the attribute.</param>
        /// <param name="value">The value of the attribute.</param>
        /// <exception cref="ArgumentNullException"><paramref name="sb"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="type"/> is not a valid attribute type.</exception>
        static void AddAttribute(StringBuilder sb, string type, object value)
        {
            if (sb == null)
            {
                throw new ArgumentNullException("sb");
            }

            if (false == RdnSequence.IsValidAttributeType(type))
            {
                throw new ArgumentOutOfRangeException("type", type, "The value is not a valid attribute type.");
            }

            if (sb.Length > 0)
            {
                // Add delimiter
                sb.Append(",");
            }

            sb.Append(type.ToUpper());

            sb.Append('=');

            var escapedValue = RdnSequence.EscapeValue(value);

            sb.Append(escapedValue);
        }

        #endregion

        #region RdnSequence class

        static class RdnSequence
        {
            #region Regular Expression

            // This information has been taken out from RFC 2253: http://www.ietf.org/rfc/rfc2253.txt

            #region Definition

            /*

RDNSequence=RDN(\s*(,|;)\s*RDN)*

RDN=Pair(\s*+\s*Pair)*

Pair=Attribute\s*=\s*Value

Attribute=(Name|OID)

Name=Alpha(Char)*

Char=(Alpha|Digit|-)

OID=(oid\.|OID\.)?Digit+(.Digit+)*

Value=(HexString|String|"QuotedString")

HexString=#HexPair+

HexPair=HexChar{2}

HexChar=[0-9A-Fa-f]

String=(StringChar|PairChar)+

QuotedString=(QuotedChar|PairChar)+

StringChar=[^\",=+<>#;]

QuotedChar=[^\"]

SpecialChar=[,=+<>#;]

EscapeOrQuoteChar=[\"]

PairChar=\(SpecialChar|EscapeOrQuoteChar|HexPair)

Alpha=ASCII letter

Digit=ASCII decimal digit


Regex options : Multiline (than name CAN contain unescaped '\n' characters, ExplicitCapture

        */

            #endregion

            #region Character classes

            /// <summary>
            /// An ASCII alphabetic character.
            /// </summary>
            readonly static string AlphaCharacter = "[A-Za-z]";

            /// <summary>
            /// An ASCII decimal digit.
            /// </summary>
            readonly static string DigitCharacter = "[0-9]";

            /// <summary>
            /// A hexadecimal character.
            /// </summary>
            readonly static string HexCharacter = "[0-9A-Fa-f]";

            /// <summary>
            /// An escape character ('\') or a quote character ('"').
            /// </summary>
            readonly static string EscapeOrQuoteChar = @"[\\""]";

            /// <summary>
            /// Not an escape character ('\') or a quote character ('"').
            /// </summary>
            readonly static string NotEscapeOrQuoteChar = @"[^\\""]";

            /// <summary>
            /// Special characters.
            /// </summary>
            readonly static string SpecialCharacter = "[,=+<>#;]";

            /// <summary>
            /// Not a special character, an escape character ('\') or a quote character ('"').
            /// </summary>
            readonly static string NotSpecialEscapeOrQuoteChar = @"[^\\"",=+<>#;]";

            #endregion

            #region Advanced character classes

            /// <summary>
            /// A pair of hexadecimal characters.
            /// </summary>
            /// <remarks>
            /// (HexChar){2}
            /// </remarks>
            readonly static string HexPair = HexCharacter + "{2}";

            /// <summary>
            /// An escaped character (uses the escape character '\' for escaping).
            /// </summary>
            /// <remarks>
            /// \(SpecialChar|QuoteChar|EscapeChar|HexPair)
            /// </remarks>
            readonly static string EscapedCharacter = @"\\(" + SpecialCharacter + "|" + EscapeOrQuoteChar + "|" + HexPair + ")";

            /// <summary>
            /// A character that can participate in an unquoted string without being escaped.
            /// </summary>
            readonly static string UnquotedStringCharacter = NotSpecialEscapeOrQuoteChar;

            /// <summary>
            /// A character that can participate in a quoted string without being escaped.
            /// </summary>
            readonly static string QuotedStringCharacter = NotEscapeOrQuoteChar;

            #endregion

            #region Basic constructs

            /// <summary>
            /// A hexadecimal string.
            /// </summary>
            /// <remarks>
            /// #(HexPair)+ = #(HexChar{2})+
            /// </remarks>
            readonly static string HexString = "#(" + HexPair + ")+?";

            /// <summary>
            /// An unquoted string.
            /// </summary>
            /// <remarks>
            /// (UnquotedStringchar|EscapedChar)+
            /// </remarks>
            readonly static string UnquotedString = "(" + UnquotedStringCharacter + "|" + EscapedCharacter + ")+?"; // Use non-gready matching to avoid capturing tralling spaces

            /// <summary>
            /// A quoted string: allows special characters to remain unescaped. However, the quote character ('"')
            /// and the escap character ('\') must be escaped.
            /// </summary>
            /// <remarks>
            /// "(QuoteStringChar|EscapedChar)+"
            /// </remarks>
            readonly static string QuotedString = @"""(" + QuotedStringCharacter + "|" + EscapedCharacter + @")+?""";

            /// <summary>
            /// A value of an attribute.
            /// </summary>
            /// <remarks>
            /// (HexString|UnquotedString|QuotedString)
            /// </remarks>
            readonly static string AttributeValue = "(?<value>" + HexString + "|" + UnquotedString + "|" + QuotedString + ")";

            /// <summary>
            /// An OID.
            /// </summary>
            /// <remarks>
            /// (oid.|OID.)?[0-9]+(.[0-9]+)*
            /// </remarks>
            readonly static string Oid = string.Format(@"(oid\.|OID\.)?{0}+(\.{0}+)*", DigitCharacter);

            /// <summary>
            /// A character that can be a part of the name of an attribute type.
            /// </summary>
            /// <remarks>
            /// (Alpha|Digit|-)
            /// </remarks>
            readonly static string AttributeTypeNameChar = "(" + AlphaCharacter + "|" + DigitCharacter + "|-)";

            /// <summary>
            /// The name of an attribute type.
            /// </summary>
            /// <remarks>
            /// Alpha(AttributeTypeNameChar)*
            /// </remarks>
            readonly static string AttributeTypeName = AlphaCharacter + AttributeTypeNameChar + "*?";

            /// <summary>
            /// An attribute type.
            /// </summary>
            /// <remarks>
            /// (OID|AttributeTypeName)
            /// </remarks>
            readonly static string AttributeType = "(?<attribute>" + Oid + "|" + AttributeTypeName + ")";

            /// <summary>
            /// Attribute type and its value.
            /// </summary>
            /// <remarks>
            /// (AttributeType=AttributeValue)
            /// </remarks>
            readonly static string AttributeTypeValuePair = string.Format(@"(?<pair>{0}\s*=\s*{1})", AttributeType, AttributeValue);

            #endregion

            #region Advanced constructs

            /// <summary>
            /// Relative Distinguished Name (RND).
            /// </summary>
            /// <remarks>
            /// AttributeTypeValuePair(+AttributeTypeValuePair)*
            /// </remarks>
            readonly static string RelativeDistinguishedName = string.Format(@"(?<rdn>{0}(\s*\+\s*{0})*)", AttributeTypeValuePair);

            /// <summary>
            /// A sequence of RNDs.
            /// </summary>
            /// <remarks>
            /// RND((,|;)RND)*
            /// </remarks>
            readonly static string RelativeDistinguishedNameSequence = string.Format(@"({0}(\s*(,|;)\s*{0})*)", RelativeDistinguishedName);

            #endregion

            static Regex _rdnSequenceRegex;

            /// <summary>
            /// Gets a regular expression that can be used to validate or parse a Relative Distinguished Name sequence.
            /// </summary>
            /// <value>A regular expression that can be used to validate or parse a RND sequence.</value>
            internal static Regex Regex
            {
                get
                {
                    if (_rdnSequenceRegex == null)
                    {
                        _rdnSequenceRegex = new Regex("^" + RelativeDistinguishedNameSequence + "$", RegexOptions.Multiline | RegexOptions.ExplicitCapture | RegexOptions.Compiled);
                    }

                    return _rdnSequenceRegex;
                }
            }

            static Regex _attributeTypeRegex;

            /// <summary>
            /// Gets a regular expression that can be used to validate an attribute type.
            /// </summary>
            /// <value>A regular expression that can be used to validate an attribute type.</value>
            static Regex AttributeTypeRegex
            {
                get
                {
                    if (_attributeTypeRegex == null)
                    {
                        _attributeTypeRegex = new Regex("^" + AttributeType + "$", RegexOptions.Compiled);
                    }

                    return _attributeTypeRegex;
                }
            }

            #endregion

            #region Constants

            /// <summary>
            /// Specifies the characters which if present in a value must be escaped.
            /// </summary>
            readonly static char[] EscapeValueCharacters = { '\\', '"', ',', '=', '+', '<', '>', '#', ';' };

            #endregion

            #region Public methods

            /// <summary>
            /// Determines whether a value is a valid attibute type.
            /// </summary>
            /// <param name="value">The value.</param>
            /// <returns>
            /// 	<c>true</c> if the value is a valid attribute type; otherwise, <c>false</c>.
            /// </returns>
            /// <exception cref="ArgumentNullException"><paramref name="value"/> is <c>null</c> or empty.</exception>
            public static bool IsValidAttributeType(string value)
            {
                if (string.IsNullOrEmpty(value))
                {
                    throw new ArgumentNullException("value");
                }

                return AttributeTypeRegex.IsMatch(value);
            }

            /// <summary>
            /// Escapes an attribute value.
            /// </summary>
            /// <param name="value">The value.</param>
            /// <returns>The escaped value.</returns>
            /// <exception cref="ArgumentNullException"><paramref name="value"/> is <c>null</c>.</exception>
            /// <exception cref="ArgumentNullException"><paramref name="value"/> is an empty <see cref="String"/>.</exception>
            /// <exception cref="ArgumentException"><paramref name="value"/> is an empty <see cref="Array"/> of <see cref="Byte"/>.</exception>
            /// <exception cref="ArgumentException"><paramref name="value"/> is neither string neither an array of bytes.</exception>
            public static string EscapeValue(object value)
            {
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }

                if (value is string)
                {
                    return EscapeValue((string)value);
                }
                else if (value is byte[])
                {
                    return EscapeValue((byte[])value);
                }
                else
                {
                    throw new ArgumentException("Must be a string or an array of bytes.", "value");
                }
            }

            /// <summary>
            /// Escapes an attribute value.
            /// </summary>
            /// <param name="value">The value.</param>
            /// <returns>The escaped value.</returns>
            /// <exception cref="ArgumentNullException"><paramref name="value"/> is <c>null</c>.</exception>
            /// <exception cref="ArgumentException"><paramref name="value"/> is empty.</exception>
            public static string EscapeValue(byte[] value)
            {
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }

                if (value.Length == 0)
                {
                    throw new ArgumentException("Must contain at least one element.", "value");
                }

                return "#" + ToHex(value);
            }

            /// <summary>
            /// Escapes an attribute value.
            /// </summary>
            /// <param name="value">The value.</param>
            /// <returns>The escaped value.</returns>
            /// <exception cref="ArgumentNullException"><paramref name="value"/> is <c>null</c> or empty.</exception>
            public static string EscapeValue(string value)
            {
                if (string.IsNullOrEmpty(value))
                {
                    throw new ArgumentNullException("value");
                }

                // Indicates if the value must be escaped
                bool needEscaping;

                // Indicates if the value must be quoted
                bool quote;

                if (char.IsWhiteSpace(value, 0)
                    || char.IsWhiteSpace(value, value.Length - 1)
                    || value[0] == '#'
                    || value.IndexOfAny(EscapeValueCharacters) >= 0
                    )
                {
                    needEscaping = true;

                    quote = true;
                }
                else
                {
                    needEscaping = false;

                    quote = false;

                    foreach (var ch in value)
                    {
                        if (ch != ' ' && char.IsWhiteSpace(ch))
                        {
                            // The character is a whitespace character that should be escaped (although not required by standard)
                            // for better compatibility / visual representation.

                            needEscaping = true;

                            quote = false;

                            break;
                        }
                    }
                }

                if (needEscaping)
                {
                    // The value must be escaped if:
                    // - Starts or ends with a white-space character
                    // - Starts with the '#' character (otherwise, it will look like a hex string)
                    // - Contains any of the characters: ",", "+", """, "\", "<", ">" or ";"

                    // Quote the value and escape the quote ('"') and the escape ('\') character if found in the value

                    var sb = new StringBuilder(value.Length + 10);

                    if (quote)
                    {
                        sb.Append('"');
                    }

                    foreach (var ch in value)
                    {
                        if (ch == '"' || ch == '\\')
                        {
                            // Escape the character
                            sb.Append('\\').Append(ch);
                        }
                        else if (ch != ' ' && char.IsWhiteSpace(ch))
                        {
                            // The character is a whitespace character that should be escaped (although not required by standard)
                            // for better compatibility / visual representation.

                            var bytes = Encoding.UTF8.GetBytes(new char[] { ch });

                            foreach (var item in bytes)
                            {
                                sb.Append('\\').Append(item.ToString("X2"));
                            }
                        }
                        else
                        {
                            sb.Append(ch);
                        }
                    }

                    if (quote)
                    {
                        sb.Append('"');
                    }

                    return sb.ToString();
                }
                else
                {
                    // The value does not need to be escaped

                    return value;
                }
            }

            /// <summary>
            /// Unescapes an attribute value.
            /// </summary>
            /// <param name="value">The value.</param>
            /// <returns>
            /// The unescaped value (either a <see cref="String"/> or an <see cref="Array"/> of <see cref="Byte"/>s).
            /// </returns>
            /// <exception cref="ArgumentNullException"><paramref name="value"/> is <c>null</c> or empty.</exception>
            /// <exception cref="ArgumentException"><paramref name="value"/> cannot be parsed.</exception>
            public static object UnescapeValue(string value)
            {
                if (string.IsNullOrEmpty(value))
                {
                    throw new ArgumentNullException("value");
                }

                if (value[0] == '#')
                {
                    // The value is a hex string

                    try
                    {
                        return ToBytes(value.Substring(1));
                    }
                    catch (FormatException exc)
                    {
                        throw new ArgumentException("Invalid value.", "value", exc);
                    }
                }
                else
                {
                    int index;

                    int endIndex;

                    if (value.Length >= 2 && value[0] == '"' && value[value.Length - 1] == '"')
                    {
                        // The value is a quoted string so remove the quotes

                        index = 1;

                        endIndex = value.Length - 1;
                    }
                    else
                    {
                        // The value is a string

                        index = 0;

                        endIndex = value.Length;
                    }

                    try
                    {
                        using (var result = new MemoryStream(value.Length))
                        {
                            while (index < endIndex)
                            {
                                var ch = value[index++];

                                if (ch == '\\')
                                {
                                    // The character is escaped

                                    ch = value[index++];

                                    if (Array.IndexOf(EscapeValueCharacters, ch) >= 0)
                                    {
                                        // The escaped character is a special character, the quote character ('"') or the escape character ('\')
                                        // so add it to the output

                                        result.WriteByte((byte)ch);
                                    }
                                    else
                                    {
                                        // The escaped character must be hex encoded

                                        var firstHexChar = ch;

                                        var secondHexChar = value[index++];

                                        var bytes = ToBytes(new string(new char[] { firstHexChar, secondHexChar }));

                                        result.Write(bytes, 0, bytes.Length);
                                    }
                                }
                                else
                                {
                                    if (ch > 255)
                                    {
                                        // The character is a unicode character

                                        var bytes = Encoding.UTF8.GetBytes(new char[] { ch });

                                        result.Write(bytes, 0, bytes.Length);
                                    }
                                    else
                                    {
                                        // he character is an ASCII character

                                        result.WriteByte((byte)ch);
                                    }
                                }
                            }

                            return Encoding.UTF8.GetString(result.GetBuffer(), 0, (int)result.Length);
                        }
                    }
                    catch (IndexOutOfRangeException)
                    {
                        throw new ArgumentException("Invalid value.", "value");
                    }
                }
            }

            #endregion

            #region Helper methods

            #region Hex

            /// <summary>
            /// The list of hexadecimal digits.
            /// </summary>
            static char[] HexadecimalDigits = 
            { 
                '0', '1', '2', '3', '4', '5', '6', '7', 
                '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 
            };

            /// <summary>
            /// The hexadecimal digit-to-value map.
            /// </summary>
            static int[] HexadecimalMap = 
            { 
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
                0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F 
            };

            /// <summary>
            /// Converts an array of bytes to a hexadecimal string.
            /// </summary>
            /// <param name="buffer">The array.</param>
            /// <returns>The hexadecimal string.</returns>
            static string ToHex(byte[] buffer)
            {
                if (buffer == null)
                {
                    throw new ArgumentNullException("buffer");
                }

                return ToHex(buffer, 0, buffer.Length);
            }

            /// <summary>
            /// Converts an array of bytes to a hexadecimal string.
            /// </summary>
            /// <param name="buffer">The array.</param>
            /// <param name="index">The index of the first byte to convert.</param>
            /// <param name="count">The number of bytes to convert.</param>
            /// <returns>The hexadecimal string.</returns>
            static string ToHex(byte[] buffer, int index, int count)
            {
                if (buffer == null)
                {
                    throw new ArgumentNullException("buffer");
                }

                if (index < 0)
                {
                    throw new ArgumentOutOfRangeException("index", index, "Must be a non-negative value.");
                }

                if (count < 0)
                {
                    throw new ArgumentOutOfRangeException("count", count, "Must be a non-negative value.");
                }

                if (index + count > buffer.Length)
                {
                    throw new ArgumentException("The index of the first byte plus the number of bytes exceeds the size of the array.");
                }

                var result = new char[count << 1];

                int i = 0;

                count += index;

                for (int k = index; k < count; k++)
                {
                    var item = buffer[k];

                    result[i++] = HexadecimalDigits[item >> 4];

                    result[i++] = HexadecimalDigits[item & 0x0F];
                }

                return new string(result);
            }

            /// <summary>
            /// Converts a hexadecimal string to a byte array.
            /// </summary>
            /// <param name="value">The string.</param>
            /// <returns>The byte array.</returns>
            static byte[] ToBytes(string value)
            {
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }

                if ((value.Length & 1) != 0)
                {
                    throw new FormatException("Invalid value.");
                }

                var result = new byte[value.Length >> 1];

                var count = 0;

                try
                {
                    for (int i = 0; i < value.Length; )
                    {
                        var value1 = HexadecimalMap[char.ToUpper(value[i++]) - '0'];

                        var value2 = HexadecimalMap[char.ToUpper(value[i++]) - '0'];

                        if (value1 >= 16 || value2 >= 16)
                        {
                            throw new FormatException("Invalid value.");
                        }

                        result[count++] = (byte)((value1 << 4) | value2);
                    }
                }
                catch (IndexOutOfRangeException)
                {
                    throw new FormatException("Invalid value.");
                }

                return result;
            }

            #endregion

            #endregion
        }

        #endregion
    }
}
