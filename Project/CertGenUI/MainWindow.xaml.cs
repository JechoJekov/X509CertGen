using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Common.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Common;
using Microsoft.Win32;
using System.ComponentModel;
using System.Globalization;
using System.Text.RegularExpressions;

namespace CertGenUI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // List of countries
            {
                var countryList = CultureInfo.GetCultures(CultureTypes.SpecificCultures)
                    .Select(x => new RegionInfo(x.LCID))
                    .Distinct()
                    .OrderBy(x => x.EnglishName);

                dropDownListCountry.Items.Add(new ComboBoxItem()); // Add an empty item
                foreach (var item in countryList)
                {
                    dropDownListCountry.Items.Add(new ComboBoxItem()
                    {
                        Content = string.Format("[{1}] {0}", item.EnglishName, item.Name),
                        Tag = item.Name,
                    });
                }
            }

            textBoxPeriod_From.SelectedDate = DateTime.UtcNow.Date;
            textBoxPeriod_To.SelectedDate = DateTime.UtcNow.Date.AddYears(10);
        }

        /// <summary>
        /// Use a field to remember the folder.
        /// </summary>
        OpenFileDialog _issuerFileDialog;

        private void buttonIssuer_BrowseCertificate_Click(object sender, RoutedEventArgs e)
        {
            if (_issuerFileDialog == null)
            {
                _issuerFileDialog = new OpenFileDialog()
                {
                    Title = "Open Issuer Certificate",
                    Filter = "PKCS#12 Certificates (.pfx; .p12)|*.pfx;*.p12|All Files (*.*)|*.*",
                    CheckFileExists = true,
                };
            }
            var result = _issuerFileDialog.ShowDialog();
            if (result == true)
            {
                textBoxIssuer_CertificatePath.Text = _issuerFileDialog.FileName;
            }
        }

        /// <summary>
        /// Use a field to remember the folder.
        /// </summary>
        SaveFileDialog _saveToFileDialog;

        private void buttonSaveTo_Browse_Click(object sender, RoutedEventArgs e)
        {
            if (_saveToFileDialog == null)
            {
                _saveToFileDialog = new SaveFileDialog()
                {
                    Title = "Save Certificate",
                    Filter = "PKCS#12 Certificates (.pfx; .p12)|*.pfx;*.p12|All Files (*.*)|*.*",
                    CheckFileExists = false,
                    CheckPathExists = true,
                    OverwritePrompt = true,
                    AddExtension = true,
                };
            }
            var result = _saveToFileDialog.ShowDialog();
            if (result == true)
            {
                textBoxSaveTo_Path.Text = _saveToFileDialog.FileName;
            }
        }

        private void buttonGenerate_Click(object sender, RoutedEventArgs e)
        {
            // TODO Validate

            X509Certificate2 issuerCertificate;

            if (false == string.IsNullOrWhiteSpace(textBoxIssuer_CertificatePath.Text))
            {
                string issuerPassword;
                if (false == PasswordDialog.Show(
                    this,
                    "Issuer Certificate Password",
                    "Please enter the password of the issuer certificate:",
                    out issuerPassword
                    ))
                {
                    return;
                }

                try
                {
                    issuerCertificate = new X509Certificate2(textBoxIssuer_CertificatePath.Text.Trim(), issuerPassword);
                }
                catch (CryptographicException exc)
                {
                    MessageBox.Show(
                        this,
                        "Could not load the certificate of the issuer:\n" + exc.Message,
                        "Error",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error
                        );
                    return;
                }
            }
            else
            {
                issuerCertificate = null;
            }

            string outputPassword;
            if (false == PasswordDialog.Show(
                this,
                "New Certificate Password",
                "Please enter a password for the NEW certificate:",
                out outputPassword
                ))
            {
                return;
            }

            var outputPath = textBoxSaveTo_Path.Text.Trim();

            var subjectName = new X501DistinguishedName()
            {
                CommonName = textBoxCommonName.Text.TrimToNull(),
                Organization = textBoxOrganization.Text.TrimToNull(),
                OrganizationalUnit = textBoxOrganizationalUnit.Text.TrimToNull(),
                Locality = textBoxLocality.Text.TrimToNull(),
                StateOrProvince = textBoxState.Text.TrimToNull(),
                Country = (dropDownListCountry.SelectedValue as string ?? dropDownListCountry.Text).TrimToNull() // "SelectedValue" is null if text is entered manually
            };

            var subjectAlternativeNames = textBoxSubjectAltNames.Text
                .Split(new char[] { '\n', '\r' })
                .Select(x => x.Trim())
                .Where(x => x.Length > 0)
                .ToList();

            if (subjectAlternativeNames.Count > 0 && false == subjectAlternativeNames.Contains(subjectName.CommonName, StringComparer.InvariantCultureIgnoreCase))
            {
                // Check if the common name seems like a DNS name
                if (Regex.IsMatch(subjectName.CommonName, @"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"))
                {
                    subjectAlternativeNames.Insert(0, subjectName.CommonName);
                }
            }

            var options = new Options()
            {
                subjectName = subjectName.ToString(),
                subjectAlternativeNames = subjectAlternativeNames.ToArray(),
                keySize = int.Parse(dropDownListKeySize.SelectedValue as string),
                serialNumber = Guid.NewGuid().ToByteArray(),
                basicKeyUsages = FindLogicalChildren<CheckBox>(checkBoxListBasicKeyUsages)
                    .Where(x => x.IsChecked == true)
                    .Select(x => (BasicKeyUsages)x.Tag)
                    .DefaultIfEmpty() // The "Aggregate" method requires at least one value
                    .Aggregate((x, y) => x | y),
                basicKeyUsagesCritical = checkBoxBasicKeyUsages_Critical.IsChecked == true,
                extendedUsages = FindLogicalChildren<CheckBox>(checkBoxListExtendedKeyUsages)
                    .Where(x => x.IsChecked == true)
                    .Select(x => (string)x.Tag)
                    .ToList(),
                extendedUsagesCritical = checkBoxExtendedKeyUsages_Critical.IsChecked == true,
                fromDate = DateTime.SpecifyKind(textBoxPeriod_From.SelectedDate.Value, DateTimeKind.Utc),
                toDate = DateTime.SpecifyKind(textBoxPeriod_To.SelectedDate.Value, DateTimeKind.Utc),
                isCA = checkBoxCA.IsChecked == true,
                caLength = int.Parse(dropDownListCA_MaxPathLength.SelectedValue as string),
                issuerCertificate = issuerCertificate,
                outputFile = System.IO.Path.HasExtension(outputPath) ? outputPath : System.IO.Path.ChangeExtension(outputPath, ".pfx"),
                outputPassword = outputPassword,
                outputCertFile = System.IO.Path.ChangeExtension(outputPath, ".cer"),
            };

            // Check if some of the output files exist
            if (File.Exists(options.outputFile))
            {
                var result = MessageBox.Show(
                    this,
                    string.Format("'{0}' already exists. Overwrite?", options.outputFile),
                    "Overwrite PKCS#12 File",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question
                    );
                if (result != MessageBoxResult.Yes)
                {
                    return;
                }
            }
            if (File.Exists(options.outputCertFile))
            {
                var result = MessageBox.Show(
                    this,
                    string.Format("'{0}' already exists. Overwrite?", options.outputCertFile),
                    "Overwrite X.509 Certificate File",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question
                    );
                if (result != MessageBoxResult.Yes)
                {
                    return;
                }
            }

            panelMain.IsEnabled = false;
            Task.Factory
                .StartNew(() => GenerateCertificate(options))
                .ContinueWith(GenerateCompleted, TaskScheduler.FromCurrentSynchronizationContext());
        }

        void GenerateCompleted(Task<byte[]> task)
        {
            if (task.Exception != null)
            {
                MessageBox.Show(
                    this,
                    "Error: " + task.Exception.InnerExceptions.First().Message,
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                    );
            }
            else
            {
                /* // Not implemented
                // Display the hash of the certificate
                var certData = task.Result;

                foreach (var alg in HashAlgorithmList)
                {
                    using (var hash = HashAlgorithm.Create(alg))
                    {
                        var binaryHash = hash.ComputeHash(certData);
                        // TODO Display in a label
                    }
                }
                */

                MessageBox.Show(
                    this,
                    "X.509 and PKCS#12 certificates generated.",
                    "Certificate Generated",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information
                    );
            }

            panelMain.IsEnabled = true;
        }

        /// <summary>
        /// The list of supported hash algorithms.
        /// </summary>
        static string[] HashAlgorithmList = { "SHA1", "SHA256", "SHA384", "SHA512", };

        #region Generate

        byte[] GenerateCertificate(Options options)
        {
            var builder = new X509CertificateBuilder();

            // If the default key container is not used accessing the key will throw a "Key not found" exception
            using (var rsa = new RSACryptoServiceProvider(options.keySize, new CspParameters() { Flags = CspProviderFlags.UseDefaultKeyContainer | CspProviderFlags.CreateEphemeralKey }))
            {
                try
                {
                    #region Key

                    builder.PublicKey = rsa;

                    #endregion

                    builder.SubjectName = options.subjectName;
                    builder.SubjectAlternativeNames = options.subjectAlternativeNames;
                    builder.SerialNumber = options.serialNumber;
                    builder.KeyUsages = options.basicKeyUsages;
                    builder.KeyUsagesCritical = options.basicKeyUsagesCritical;
                    if (options.extendedUsages != null)
                    {
                        builder.ExtendedKeyUsages = options.extendedUsages.ToArray();
                    }
                    builder.ExtendedKeyUsagesCritical = options.extendedUsagesCritical;
                    builder.NotBefore = options.fromDate;
                    builder.NotAfter = options.toDate;
                    builder.IsCertificateAuthority = options.isCA;
                    builder.CertificateAuthorityPathLength = options.caLength;

                    if (options.issuerCertificate == null)
                    {
                        builder.SelfSign(rsa);
                    }
                    else
                    {
                        builder.Sign(options.issuerCertificate);
                    }

                    File.WriteAllBytes(options.outputFile, builder.ExportPkcs12(rsa, options.outputPassword, 1000));

                    var certData = builder.Export();

                    if (false == string.IsNullOrEmpty(options.outputCertFile))
                    {
                        File.WriteAllBytes(options.outputCertFile, certData);
                    }

                    return certData;
                }
                finally
                {
                    // Remove the key from the key container. Otherwise, the key will be kept on the file
                    // system which is completely undesirable.
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        #endregion

        #region Helper methods

        /// <summary>
        /// Enumerates all logical children of the specified type.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="element"></param>
        /// <returns></returns>
        static IEnumerable<T> FindLogicalChildren<T>(DependencyObject element) where T : DependencyObject
        {
            if (element == null)
            {
                throw new ArgumentNullException("element");
            }

            foreach (var child in LogicalTreeHelper.GetChildren(element).OfType<DependencyObject>())
            {
                if (child is T)
                {
                    yield return (T)child;
                }

                foreach (T childOfChild in FindLogicalChildren<T>(child))
                {
                    yield return childOfChild;
                }
            }
        }

        #endregion

        #region Inner types

        class Options
        {
            public int keySize;
            public string subjectName;
            public string[] subjectAlternativeNames;
            public byte[] serialNumber;
            public BasicKeyUsages basicKeyUsages;
            public bool basicKeyUsagesCritical;
            public IList<string> extendedUsages;
            public bool extendedUsagesCritical;
            public DateTime fromDate;
            public DateTime toDate;
            public bool isCA;
            public int caLength;
            public X509Certificate2 issuerCertificate;
            public string outputFile;
            public string outputPassword;
            public string outputCertFile;
        }

        class Data : IDataErrorInfo
        {
            public string Error
            {
                get { throw new NotImplementedException(); }
            }

            public string this[string columnName]
            {
                get { throw new NotImplementedException(); }
            }
        }

        #endregion
    }
}
