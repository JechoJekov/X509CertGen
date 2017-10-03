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
using System.Windows.Shapes;

namespace CertGenUI
{
    /// <summary>
    /// Interaction logic for PasswordDialog.xaml
    /// </summary>
    public partial class PasswordDialog : Window
    {
        PasswordDialog()
        {
            InitializeComponent();
        }

        public static bool Show(Window owner, string title, string prompt, out string password)
        {
            var dialog = new PasswordDialog()
            {
                Owner = owner,
                Title = title,
            };
            dialog.label.Text = prompt;

            if (dialog.ShowDialog() == true)
            {
                password = dialog.passwordBox.Password;
                return true;
            }
            else
            {
                password = null;
                return false;
            }
        }

        private void buttonOK_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
        }
    }
}
