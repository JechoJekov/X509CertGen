using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ComponentModel;
using System.Reflection;
using Common.Security.Cryptography.X509Certificates;

namespace CertGen
{
    class Program
    {
        #region Constants

        const int ExitCode_CommandLineError = 1;

        const int ExitCode_ProcessingError = 2;

        const int DefaultKeySize = 2048;

        /// <summary>
        /// The list of hash algorithms names that can be specified on the command line.
        /// </summary>
        static string[] ValidHashAlgorithmList = { "SHA1", "SHA256", "SHA384", "SHA512", "SHA-256", "SHA-384", "SHA-512", };

        /// <summary>
        /// The list of supported hash algorithms.
        /// </summary>
        static string[] HashAlgorithmList = { "SHA1", "SHA256", "SHA384", "SHA512", };

        #endregion

        static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Help();

                return 0;
            }

            var command = args[0];

            if (command.Equals("-h", StringComparison.OrdinalIgnoreCase)
                || command.Equals("/h", StringComparison.OrdinalIgnoreCase)
                || command.Equals("-?", StringComparison.OrdinalIgnoreCase)
                || command.Equals("/?", StringComparison.OrdinalIgnoreCase)
                || command.Equals("?", StringComparison.OrdinalIgnoreCase))
            {
                // Display the help screen 
                Help();
                return 0;
            }
            else if (command.Equals("c", StringComparison.OrdinalIgnoreCase))
            {
                // Generate a certificate

                if (args.Length < 2)
                {
                    Error("Too few arguments were specified.");
                    return ExitCode_CommandLineError;
                }

                #region Arguments
                var processCommandLinePath = true;

            Arguments:

                var argIndex = 1;

                string outputFile = null;
                string outputCertFile = null;
                string commonOutputName = null;
                string outputPassword = null;
                int keySize = DefaultKeySize;
                string subjectName = null;
                IList<string> subjectAlternativeNameList = null;
                var basicKeyUsages = BasicKeyUsages.None;
                bool basicKeyUsagesCritical = false;
                var extendedUsages = new List<string>();
                bool extendedUsagesCritical = false;
                DateTime fromDate = DateTime.UtcNow.Date; // The date only
                DateTime toDate = fromDate.AddYears(1);
                bool toDateExplicitlySet = false;
                int years = 0;
                bool isCA = false;
                int caLength = -1;
                byte[] serialNumber = null;
                string issuerPath = null;
                string issuerPassword = null;
                string commandLinePath = null;

                #region Collect

                while (argIndex < args.Length)
                {
                    var argument = args[argIndex++].ToLower();

                    if (argument.Length > 0 && argument[0] == '/')
                    {
                        argument = '-' + argument.Substring(1);
                    }

                    try
                    {
                        switch (argument)
                        {
                            #region Output file
                            case "-o":
                                outputFile = args[argIndex++];
                                break;
                            case "-oc":
                                outputCertFile = args[argIndex++];
                                break;
                            case "-on":
                                commonOutputName = args[argIndex++];
                                break;
                            case "-op":
                                outputPassword = args[argIndex++];
                                break;
                            #endregion
                            #region Basic
                            case "-k":
                                if (int.TryParse(args[argIndex++], out keySize) && keySize > 0)
                                {
                                    break;
                                }
                                else
                                {
                                    Error("Invalid key size.");
                                    return ExitCode_CommandLineError;
                                }
                            case "-s":
                                subjectName = args[argIndex++];
                                try
                                {
                                    X501DistinguishedName.Parse(subjectName);
                                }
                                catch (FormatException exc)
                                {
                                    Error("Invalid subject distinguished name: {0}", exc.Message);
                                    return ExitCode_CommandLineError;
                                }
                                break;
                            case "-sa":
                                subjectAlternativeNameList = args[argIndex++].Split(',').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
                                break;
                            case "-sn":
                                var serialNumberText = args[argIndex++];
                                if (serialNumberText.StartsWith("0x", StringComparison.InvariantCultureIgnoreCase)
                                    || serialNumberText.StartsWith("x", StringComparison.InvariantCultureIgnoreCase))
                                {
                                    // A hexadecimal string
                                    try
                                    {
                                        serialNumber = ToBytes(serialNumberText.Substring(1));
                                        break;
                                    }
                                    catch (FormatException)
                                    {
                                        Error("Invalid serial number: invalid hexadecimal string.");
                                        return ExitCode_CommandLineError;
                                    }
                                }
                                else
                                {
                                    // An integer number
                                    long serialNumberLong;
                                    if (long.TryParse(serialNumberText, out serialNumberLong))
                                    {
                                        serialNumber = BitConverter.GetBytes(serialNumberLong);
                                        // Remove trailing zero bytes
                                        serialNumber = serialNumber.Reverse().SkipWhile(x => x == 0).Reverse().ToArray();
                                        if (serialNumber.Length == 0)
                                        {
                                            serialNumber = new byte[] { 0 };
                                        }
                                        break;
                                    }
                                    else
                                    {
                                        Error("Invalid serial number: the specified value is not an integer or is too large.");
                                        return ExitCode_CommandLineError;
                                    }
                                }
                            #endregion
                            #region Key usage
                            case "-bu":
                            case "-buc":
                                basicKeyUsagesCritical = argument == "-buc";
                                try
                                {
                                    basicKeyUsages = (BasicKeyUsages)Enum.Parse(typeof(BasicKeyUsages), args[argIndex++], true);
                                }
                                catch (ArgumentException exc)
                                {
                                    Error("Invalid certificate usages: {0}", exc.Message);
                                    return ExitCode_CommandLineError;
                                }
                                break;
                            case "-eu":
                            case "-euc":
                                extendedUsagesCritical = argument == "-euc";
                                foreach (var item in args[argIndex++].Split(','))
                                {
                                    var usage = item.Trim();

                                    if (item.Length == 0)
                                    {
                                        continue;
                                    }

                                    string result;

                                    switch (item.ToLower())
                                    {
                                        case "serverauthentication":
                                            result = ExtendedKeyUsages.ServerAuthentication;
                                            break;
                                        case "clientauthentication":
                                            result = ExtendedKeyUsages.ClientAuthentication;
                                            break;
                                        case "codesigning":
                                            result = ExtendedKeyUsages.CodeSigning;
                                            break;
                                        case "emailprotection":
                                            result = ExtendedKeyUsages.EmailProtection;
                                            break;
                                        case "timestamping":
                                            result = ExtendedKeyUsages.TimeStamping;
                                            break;
                                        case "ocspsigning":
                                            result = ExtendedKeyUsages.OCSPSigning;
                                            break;
                                        default:
                                            if (item.StartsWith("oid:"))
                                            {
                                                result = item.Substring(4);
                                                break;
                                            }
                                            else
                                            {
                                                Error("Invalid extended usage: '{0}'.", item);
                                                return ExitCode_CommandLineError;
                                            }
                                    }

                                    extendedUsages.Add(result);
                                }
                                break;
                            #endregion
                            #region Validity period
                            case "-f":
                                if (DateTime.TryParse(args[argIndex++], out fromDate))
                                {
                                    break;
                                }
                                else
                                {
                                    Error("Invalid validity period starting date.");
                                    return ExitCode_CommandLineError;
                                }
                            case "-t":
                                if (DateTime.TryParse(args[argIndex++], out toDate))
                                {
                                    toDateExplicitlySet = true;
                                    break;
                                }
                                else
                                {
                                    Error("Invalid validity period ending date.");
                                    return ExitCode_CommandLineError;
                                }
                            case "-y":
                                if (int.TryParse(args[argIndex++], out years) && years > 0)
                                {

                                    break;
                                }
                                else
                                {
                                    Error("Invalid number of years for which the certificate is valid.");
                                    return ExitCode_CommandLineError;
                                }
                            #endregion
                            #region CA
                            case "-ca":
                                isCA = true;
                                break;
                            case "-calen":
                                if (int.TryParse(args[argIndex++], out caLength) && caLength >= 0)
                                {
                                    break;
                                }
                                else
                                {
                                    Error("Invalid 'calen' value.");
                                    return ExitCode_CommandLineError;
                                }
                            #endregion
                            #region Issuer
                            case "-i":
                                issuerPath = args[argIndex++];
                                break;
                            case "-ip":
                                issuerPassword = args[argIndex++];
                                break;
                            #endregion
                            #region Other
                            case "-r":
                                commandLinePath = args[argIndex++];
                                break;
                            #endregion
                            #region Basic
                            case "?":
                            case "-?":
                            case "-h":
                                Help();
                                return ExitCode_CommandLineError;
                            default:
                                Error("Invalid argument: '{0}'.", argument);
                                return ExitCode_CommandLineError;
                            #endregion
                        }
                    }
                    catch (IndexOutOfRangeException)
                    {
                        Error("'{0}' must be followed by an additional parameter.", argument);

                        return ExitCode_CommandLineError;
                    }
                }

                #endregion

                #region Process

                if (processCommandLinePath && false == string.IsNullOrEmpty(commandLinePath))
                {
                    if (false == File.Exists(commandLinePath))
                    {
                        Error("The file containing command line arguments was not found.");
                        return ExitCode_CommandLineError;
                    }

                    string[] readCommandLineArguments;

                    try
                    {
                        readCommandLineArguments = File.ReadAllLines(commandLinePath);
                    }
                    catch (Exception exc)
                    {
                        Error("Could not read the file containing command line arguments: {0}", exc.Message);
                        return ExitCode_CommandLineError;
                    }

                    try
                    {
                        var readCommandLine = string.Join(" ", readCommandLineArguments);

                        readCommandLineArguments = ParseCommandLine(readCommandLine);
                    }
                    catch (Win32Exception exc)
                    {
                        Error("Could not parse the arguments read from file: {0}", exc.Message);
                        return ExitCode_CommandLineError;
                    }

                    // Indicate that the command line arguments has been already processed
                    processCommandLinePath = false;

                    // The arguments specified on the command line MUST override the arguments read from the file.
                    // Therefore, they must follow the read arguments in the array.
                    // Move the command argument at the front
                    args = new string[] { args[0] }.Concat(readCommandLineArguments).Concat(args.Skip(1)).ToArray();

                    Console.WriteLine();

                    // Reprocess the command-line arguments
                    goto Arguments;
                }

                if (false == string.IsNullOrEmpty(commonOutputName))
                {
                    // Apply the common name to the other parameters

                    if (string.IsNullOrEmpty(outputFile))
                    {
                        outputFile = Path.ChangeExtension(commonOutputName, ".pfx");
                    }
                    if (string.IsNullOrEmpty(outputCertFile))
                    {
                        outputCertFile = Path.ChangeExtension(commonOutputName, ".cer");
                    }
                }

                if (string.IsNullOrEmpty(outputFile))
                {
                    Error("An output file must be specified.");
                    return ExitCode_CommandLineError;
                }

                if (string.IsNullOrEmpty(subjectName))
                {
                    Error("A subject distinguished name (DN) must be specified.");
                    return ExitCode_CommandLineError;
                }

                if (outputPassword == null)
                {
                    Console.Write("Enter OUTPUT file password: ");
                    outputPassword = ReadPassword();
                }

                X509Certificate2 issuerCertificate;

                if (false == string.IsNullOrEmpty(issuerPath))
                {
                    if (issuerPassword == null)
                    {
                        Console.Write("Enter ISSUER certificate password: ");
                        issuerPassword = ReadPassword();
                    }

                    try
                    {
                        issuerCertificate = new X509Certificate2(issuerPath, issuerPassword, X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.Exportable);
                    }
                    catch (CryptographicException exc)
                    {
                        Error("Cannot load the certificate of the issuer: {0}", exc.Message);
                        return ExitCode_CommandLineError;
                    }

                    if (false == issuerCertificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(x => x.CertificateAuthority))
                    {
                        Error("The certificate of the issuer must be a CA.");
                        return ExitCode_CommandLineError;
                    }

                    if (false == issuerCertificate.HasPrivateKey)
                    {
                        Error("The certificate of the issuer must has an associated private key.");
                        return ExitCode_CommandLineError;
                    }
                }
                else
                {
                    issuerCertificate = null;
                }

                if (serialNumber == null)
                {
                    serialNumber = Guid.NewGuid().ToByteArray();
                }

                if (false == toDateExplicitlySet && years > 0)
                {
                    toDate = fromDate.AddYears(years);
                }

                if (fromDate >= toDate)
                {
                    Error("The ending of the validity period must follow its ending.");
                    return ExitCode_CommandLineError;
                }

                #endregion

                #endregion

                #region Work

                try
                {
                    var builder = new X509CertificateBuilder();

                    Console.Write("Generating RSA key...");

                    // If the default key container is not used accessing the key will throw a "Key not found" exception
                    using (var rsa = new RSACryptoServiceProvider(keySize, new CspParameters() { Flags = CspProviderFlags.UseDefaultKeyContainer | CspProviderFlags.CreateEphemeralKey }))
                    {
                        try
                        {
                            #region Key

                            Console.WriteLine(" Done");

                            builder.PublicKey = rsa;

                            #endregion

                            builder.SubjectName = subjectName;
                            builder.SubjectAlternativeNames = subjectAlternativeNameList;
                            builder.SerialNumber = serialNumber;
                            builder.KeyUsages = basicKeyUsages;
                            builder.KeyUsagesCritical = basicKeyUsagesCritical;
                            builder.ExtendedKeyUsages = extendedUsages.ToArray();
                            builder.ExtendedKeyUsagesCritical = extendedUsagesCritical;
                            builder.NotBefore = fromDate;
                            builder.NotAfter = toDate;
                            builder.IsCertificateAuthority = isCA;
                            builder.CertificateAuthorityPathLength = caLength;

                            if (issuerCertificate == null)
                            {
                                builder.SelfSign(rsa);
                            }
                            else
                            {
                                builder.Sign(issuerCertificate);
                            }

                            File.WriteAllBytes(outputFile, builder.ExportPkcs12(rsa, outputPassword, 1000));

                            var certData = builder.Export();

                            if (false == string.IsNullOrEmpty(outputCertFile))
                            {
                                File.WriteAllBytes(outputCertFile, certData);
                            }

                            // Display the hash of the certificate

                            Console.WriteLine("Certificate hash:");

                            foreach (var alg in HashAlgorithmList)
                            {
                                using (var hash = HashAlgorithm.Create(alg))
                                {
                                    var binaryHash = hash.ComputeHash(certData);
                                    Console.WriteLine("{0,-8}{1}", alg, BitConverter.ToString(binaryHash).Replace("-", ""));
                                }
                            }
                        }
                        finally
                        {
                            // Remove the key from the key container. Otherwise, the key will be kept on the file
                            // system which is completely undesirable.
                            rsa.PersistKeyInCsp = false;
                        }
                    }
                }
                catch (Exception exc)
                {
                    Error("Unexpected error: {0}", exc.Message);

                    return ExitCode_ProcessingError;
                }

                #endregion

                Console.WriteLine();

                Console.WriteLine("All done.");

                return 0;
            }
            else if (command.Equals("h", StringComparison.OrdinalIgnoreCase))
            {
                // Output the hash of a certificate

                if (args.Length < 2)
                {
                    Error("Too few arguments were specified.");
                    return ExitCode_CommandLineError;
                }

                #region Arguments

                var argIndex = 1;

                string fileName = args[argIndex++];
                string password = null;
                string algorithm = null;

                while (argIndex < args.Length)
                {
                    var argument = args[argIndex++].ToLower();

                    if (argument.Length > 0 && argument[0] == '/')
                    {
                        argument = '-' + argument.Substring(1);
                    }

                    try
                    {
                        switch (argument)
                        {
                            case "-p":
                                password = args[argIndex++];
                                break;
                            case "-a":
                                algorithm = args[argIndex++];
                                if (false == ValidHashAlgorithmList.Contains(algorithm, StringComparer.OrdinalIgnoreCase))
                                {
                                    Error("Invalid hash algorithm: '{0}'.", algorithm);
                                    return ExitCode_CommandLineError;
                                }
                                break;
                            #region Basic
                            case "?":
                            case "-?":
                            case "-h":
                                Help();
                                return ExitCode_CommandLineError;
                            default:
                                Error("Invalid argument: '{0}'.", argument);
                                return ExitCode_CommandLineError;
                            #endregion
                        }
                    }
                    catch (IndexOutOfRangeException)
                    {
                        Error("'{0}' must be followed by an additional parameter.", argument);

                        return ExitCode_CommandLineError;
                    }
                }

                #endregion

                #region Processing

                try
                {
                    #region Load file

                    if (false == File.Exists(fileName))
                    {
                        Error("The certificate file was not found.");
                        return ExitCode_CommandLineError;
                    }

                    X509Certificate2 certificate = null;

                    if (false == fileName.EndsWith(".pfx", StringComparison.InvariantCultureIgnoreCase))
                    {
                        // Assume that the file may be in DER format

                        try
                        {
                            certificate = new X509Certificate2(fileName);
                        }
                        catch (CryptographicException)
                        {
                            // The file may be encrypted so ignore the error
                        }
                    }

                    if (certificate == null)
                    {
                        if (password == null)
                        {
                            // Prompt the user for a password
                            Console.Write("Enter PFX password: ");
                            password = ReadPassword();
                        }

                        try
                        {
                            certificate = new X509Certificate2(fileName, password);
                        }
                        catch (CryptographicException exc)
                        {
                            // The file may be encrypted so ignore the error
                            Error("Cannot load the certificate: {0}", exc.Message);
                            return ExitCode_CommandLineError;
                        }
                    }

                    #endregion

                    if (string.Equals(algorithm, "SHA1", StringComparison.OrdinalIgnoreCase))
                    {
                        // Only the SHA1 hash must be displayed
                        Console.WriteLine(certificate.GetCertHashString());
                    }
                    else if (algorithm != null)
                    {
                        // Display the hash only for the specified algorithm

                        using (var hash = HashAlgorithm.Create(algorithm))
                        {
                            var binaryHash = hash.ComputeHash(certificate.GetRawCertData());
                            Console.WriteLine(BitConverter.ToString(binaryHash).Replace("-", ""));
                        }
                    }
                    else
                    {
                        // Display the hash for all supported algorithms

                        var certData = certificate.GetRawCertData();

                        foreach (var alg in HashAlgorithmList)
                        {
                            using (var hash = HashAlgorithm.Create(alg))
                            {
                                var binaryHash = hash.ComputeHash(certData);
                                Console.WriteLine("{0,-8}{1}", alg, BitConverter.ToString(binaryHash).Replace("-", ""));
                            }
                        }
                    }
                }
                catch (Exception exc)
                {
                    Error("Unexpected error: {0}", exc.Message);

                    return ExitCode_ProcessingError;
                }

                #endregion

                return 0;
            }
            else
            {
                Error("Unknown command '{0}'. Run the program without arguments to see the help screen.", command);
                return ExitCode_CommandLineError;
            }
        }

        #region Error

        /// <summary>
        /// Displays an error message.
        /// </summary>
        /// <param name="message">The message to display.</param>
        static void Error(string message)
        {
            Console.WriteLine();

            Console.WriteLine("ERROR: {0}", message);

            Console.WriteLine();
        }

        /// <summary>
        /// Displays an error message.
        /// </summary>
        /// <param name="format">The format string to display.</param>
        /// <param name="arguments">The arguments of the format string.</param>
        static void Error(string format, params object[] arguments)
        {
            Error(string.Format(format, arguments));
        }

        #endregion

        #region Help

        /// <summary>
        /// Displays 
        /// </summary>
        static void Help()
        {
            Console.WriteLine(@"
X.509 certificate tool

Usage: {0} <command> <arguments>

Commands:
    c               Creates a new X.509 RSA certificate.
    h               Outputs one or more cryptographic hashes of a certificate.

------------------------------------------------------------------------------

Arguments for the 'c' command:
    -o <file>       REQUIRED/OPTIONAL
                    The file to which to save the generated certificate in PFX
                    (PKCS#12) format.
                    The argument is not required if '-on' is specified.

    -op <password>  OPTIONAL
                    The password with which to encrypt the private key stored
                    in the PFX file. If not specified you will be prompted.

    -oc <file>      OPTIONAL
                    The file to which to save the generated certificate in DER
                    format (without its private key).
    
    -on <file>      OPTIONAL
                    A common file name without extension for the files to 
                    which to save the generated certificate in PFX (PKCS#12) 
                    format and in DER format. '.pfx' extension is added for 
                    the PFX format file and '.cer' extension is added for the
                    DER format file.

    -k <number>     OPTIONAL
                    The size of the RSA key in bits. Should be at least 1024.
                    The default is {1}.

    -s <dn>         REQUIRED
                    Subject's distinguished name (DN). 
                    Example: 'CN=Test,O=Test Organization,OU=Test Department'

    -sa <list>      OPTIONAL
                    A command-separated list of subject's alternative names.
                    Example: 'localhost,127.0.0.1'
    
    -bu[c] <usages> OPTIONAL
                    A comma-separated list of the certificate's intended 
                    usages. The 'c' switch indicates that the usage must be 
                    marked as critical.

                    Supported values:
                        DigitalSignature        Verify a digital signature
                                                other than non-repudiation,
                                                certificate or CLR signing
                        NonRepudiation          Verify a digital signature
                                                that protects against the 
                                                signing entity falsely denying 
                                                some action, excluding
                                                certificate or CRL signing
                        KeyEncipherment         Encrypt cryptographic keys
                        DataEncipherment        Encrypt data other than keys
                        KeyAgreement            Key agreement (e.g. during an
                                                SSL session)
                        KeyCertSign             Signing of certificates (valid
                                                only for cA)
                        CRLSign                 Verifying a digital signature
                                                of a CRL
                        EncipherOnly            Valid only with key agreement.
                                                The key can be used only to
                                                encrypt data during the
                                                agreement.
                        DecipherOnly            Valid only with key agreement.
                                                The key can be used only to
                                                decrypt data during the
                                                agreement.

                    Example: 'DigitalSignature,NonRepudiation'

    -eu[c] <usages> OPTIONAL
                    A comma-separated list of certificate's intended extended
                    usages. The 'c' switch indicates that the usage must be
                    marked as critical.

                    Supported values:
                        ServerAuthentication    SSL server certificate
                        ClientAuthentication    SSL client certificate
                        CodeSigning             Sing code
                        EmailProtection         Protect e-mail (signing, 
                                                encryption, key agreement)
                        TimeStamping            Bind the hash of an object to
                                                a time from a trusted time 
                                                source
                        OCSPSigning             The corresponding private key
                                                may be used by an authority 
                                                to sign OCSP-Responses
                        OID:<OID>               A custom usage specified by an
                                                OID

                    Example: 'ServerAuthentication,OID:1.3.6.1.5.5.7.3.2'

    -f <datetime>   OPTIONAL
                    The UTC date and time (in universal format or a format
                    supported by the operating system) from which the 
                    certificate is valid. If not specified the current date
                    is assumed.
                    Examples: 
                        Universal format: '2008-04-23', '2008-05-18 18:40'
                        US English format: '04/23/2008', '05/18/2008 6:40 pm'
    
    -t <datetime>   OPTIONAL
                    The UTC date and time until which the certificate is 
                    valid. If not specified the current date and time plus one
                    year is assumed.

    -y <years>      OPTIONAL
                    The number of years the certificate is valid if '-t' is
                    not specified.

    -ca             OPTIONAL
                    Indicates that the certificate is a certificate authority
                    (CA) certificate.

    -calen <number> OPTIONAL
                    The maximum number of CA certificates that may follow 
                    this certificate in a certification path. Valid only with
                    the '-ca' argument.

    -sn <number>    OPTIONAL
                    The serial number of the certificate. If not specified a
                    random 128-bit number is generated.
                    The value can be an integer number (such as '1289') or a
                    hexadecimal string (e.g. '0x2B7D9C42').
                    Examples: '1024', '0x0004'

    -i <file>       OPTIONAL
                    The certificate of the issuer in (PKCS#12) format.

    -ip <password>  OPTIONAL
                    The password with which the issuer's certificate is 
                    protected. If not specified you will be prompted.

    -r <file>       OPTIONAL
                    A text file from which to load command line arguments. 
                    The arguments loaded from the file are merged with the 
                    arguments specified on the command line with precedence 
                    of the latter.
                    The arguments specified in the file can span multiple 
                    lines.
                    Example file content:
                        -k 1024
                        -s ""CN=Test, C=US, S=CA""
                        -ca -calen 3

Examples for the 'c' command:

{0} c -on test -s ""CN=Test, C=US, S=CA""
    Generates a self-signed certificate with {1} bit RSA key.

{0} c -o test.pfx -oc test.cer -s ""CN=Test, C=US, S=CA""
    Generates a self-signed certificate with {1} bit RSA key.

{0} c -o test.pfx -s ""CN=Test, C=US, S=CA"" -i ca.pfx
    Generates an end-user certificate signed by a root or intermediate CA.

{0} c -o test.pfx -s ""CN=Test, C=US, S=CA"" -ca -calen 3
    Generates a root CA certificate. The certificate can be followed by up to
    three intermediate CA certificates in a certification path.

{0} c -o test.pfx -s ""CN=Test, C=US, S=CA"" -i ca.pfx -ca
    Generates an intermediate CA certificate signed by a root or intermediate
    CA.

------------------------------------------------------------------------------

Arguments for the 'h' command:
    <file>          REQUIRED
                    The file in PKCS#12 (PFX) or DER format of which to output 
                    the hash.
    
    -op <password>  OPTIONAL
                    The password used to encrypt the private key if the file
                    is in PKCS#12 (PFX) format.
                    If the file is in PKCS#12 format and this argument is not
                    specified then you will be prompted.
    
    -a <algorithm>  OPTIONAL
                    The algorithm to use to compute the hash. Can be one of 
                    the following: 'SHA1', 'SHA256', 'SHA384', 'SHA512'
                    If not specified then the program outputs the hash for 
                    each of the algorithms.

Examples for the 'h' command:

{0} h test.cer
    Outputs the hash for each of the supported algorithms.

{0} h test.cer -a SHA1
    Outputs the hash for the SHA1 algorithm.

{0} h test.pfx -a SHA256
    Outputs the hash for the SHA256 algorithm.
",
                Path.GetFileName(new Uri(Assembly.GetCallingAssembly().CodeBase).LocalPath),
                DefaultKeySize
                );
        }

        #endregion

        #region Helper methods

        /// <summary>
        /// Reads a password from the console.
        /// </summary>
        /// <returns>The password.</returns>
        static string ReadPassword()
        {
            var password = "";

            ConsoleKeyInfo key;

            while ((key = Console.ReadKey(true)).Key != ConsoleKey.Enter)
            {
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password = password.Substring(0, password.Length - 1);
                    }
                }
                else
                {
                    password += key.KeyChar;
                }
            }

            Console.WriteLine();

            return password;
        }

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
        /// Converts a hexadecimal string to a byte array.
        /// </summary>
        /// <param name="value">The string.</param>
        /// <returns>The byte array.</returns>
        public static byte[] ToBytes(string value)
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

        /// <summary>
        /// Parses a command line.
        /// </summary>
        /// <param name="commandLine">The commend line.</param>
        /// <returns>The arguments found on the line.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="commandLine"/> is null or empty.</exception>
        /// <exception cref="Win32Exception">An error occured.</exception>
        static string[] ParseCommandLine(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine))
            {
                throw new ArgumentNullException("commandLine");
            }

            int argumentCount;

            var argumentsIntPtr = CommandLineToArgvW(commandLine, out argumentCount);

            if (argumentsIntPtr == IntPtr.Zero)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                var result = new string[argumentCount];

                for (var i = 0; i < result.Length; i++)
                {
                    var argumentIntPtr = Marshal.ReadIntPtr(argumentsIntPtr, i * IntPtr.Size);

                    result[i] = Marshal.PtrToStringUni(argumentIntPtr);
                }

                return result;
            }
            finally
            {
                // Free memory obtained by CommandLineToArgW.
                LocalFree(argumentsIntPtr);
            }
        }

        #endregion

        #region Native helper methods

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CommandLineToArgvW(string lpCmdLine, out int pNumArgs);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);

        #endregion
    }
}
