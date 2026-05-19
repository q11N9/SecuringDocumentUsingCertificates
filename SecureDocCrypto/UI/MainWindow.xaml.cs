#nullable disable
using Microsoft.Win32;
using SecureDocCrypto.Core;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace SecureDocCrypto.UI
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            RefreshCertificateStore();
        }

        private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ButtonState == MouseButtonState.Pressed)
                DragMove();
        }

        private void BtnMinimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void BtnMaximize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void BtnBrowseEncryptInput_Click(object sender, RoutedEventArgs e)
        {
            TxtEncryptInput.Text = PickOpenFile("Chọn tài liệu cần mã hóa|*.*");
        }

        private void BtnBrowsePublicKey_Click(object sender, RoutedEventArgs e)
        {
            TxtPublicKeyPath.Text = PickOpenFile("Certificate Public Key (*.cer;*.crt;*.der)|*.cer;*.crt;*.der|All files (*.*)|*.*");
        }

        private void BtnBrowseDecryptInput_Click(object sender, RoutedEventArgs e)
        {
            TxtDecryptInput.Text = PickOpenFile("PKCS#7/CMS encrypted file (*.p7m;*.p7b)|*.p7m;*.p7b|All files (*.*)|*.*");
        }

        private void BtnBrowsePrivateKey_Click(object sender, RoutedEventArgs e)
        {
            TxtPrivateKeyPath.Text = PickOpenFile("Private certificate (*.pfx;*.p12)|*.pfx;*.p12|All files (*.*)|*.*");
        }

        private void BtnBrowseSignInput_Click(object sender, RoutedEventArgs e)
        {
            TxtSignInput.Text = PickOpenFile("Chọn tài liệu cần ký|*.*");
        }

        private void BtnBrowseSignerKey_Click(object sender, RoutedEventArgs e)
        {
            TxtSignerKeyPath.Text = PickOpenFile("Private certificate (*.pfx;*.p12)|*.pfx;*.p12|All files (*.*)|*.*");
        }

        private void BtnBrowseVerifyInput_Click(object sender, RoutedEventArgs e)
        {
            TxtVerifyInput.Text = PickOpenFile("Signed CMS file (*.p7m;*.p7s;*.p7b)|*.p7m;*.p7s;*.p7b|All files (*.*)|*.*");
        }

        private void BtnExecuteEncrypt_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                EnsureFileSelected(TxtEncryptInput.Text, "Vui lòng chọn tài liệu cần mã hóa.");
                EnsureFileSelected(TxtPublicKeyPath.Text, "Vui lòng chọn chứng thư Public Key.");

                string outputPath = PickSaveFile(
                    "Lưu file đã mã hóa",
                    "Encrypted CMS (*.p7m)|*.p7m|All files (*.*)|*.*",
                    Path.GetFileName(TxtEncryptInput.Text) + ".p7m");

                if (string.IsNullOrWhiteSpace(outputPath))
                    return;

                X509Certificate2 cert = CertProvider.LoadPublicKey(TxtPublicKeyPath.Text);
                CryptoEngine.EncryptFile(TxtEncryptInput.Text, outputPath, cert);

                SetStatus($"Mã hóa thành công: {outputPath}");
                MessageBox.Show("Mã hóa tài liệu thành công.", "Thành công", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                ShowError(ex);
            }
        }

        private void BtnExecuteDecrypt_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                EnsureFileSelected(TxtDecryptInput.Text, "Vui lòng chọn file đã mã hóa.");
                EnsureFileSelected(TxtPrivateKeyPath.Text, "Vui lòng chọn chứng thư Private Key.");

                string outputPath = PickSaveFile(
                    "Lưu file đã giải mã",
                    "All files (*.*)|*.*",
                    RemoveKnownExtension(Path.GetFileName(TxtDecryptInput.Text), ".p7m"));

                if (string.IsNullOrWhiteSpace(outputPath))
                    return;

                X509Certificate2 cert = CertProvider.LoadPrivateKey(TxtPrivateKeyPath.Text, TxtPrivateKeyPassword.Password);
                CryptoEngine.DecryptFile(TxtDecryptInput.Text, outputPath, cert);

                SetStatus($"Giải mã thành công: {outputPath}");
                MessageBox.Show("Giải mã tài liệu thành công.", "Thành công", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                ShowError(ex);
            }
        }

        private void BtnExecuteSign_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                EnsureFileSelected(TxtSignInput.Text, "Vui lòng chọn tài liệu cần ký.");
                EnsureFileSelected(TxtSignerKeyPath.Text, "Vui lòng chọn chứng thư ký số Private Key.");

                X509Certificate2 signerCert = CertProvider.LoadPrivateKey(TxtSignerKeyPath.Text, TxtSignerPassword.Password);

                int selectedIndex = ComboSignType.SelectedIndex;

                if (selectedIndex == 0)
                {
                    string outputPath = PickSaveFile(
                        "Lưu file chữ ký CAdES/CMS",
                        "Signed CMS (*.p7m)|*.p7m|All files (*.*)|*.*",
                        Path.GetFileName(TxtSignInput.Text) + ".signed.p7m");

                    if (string.IsNullOrWhiteSpace(outputPath))
                        return;

                    bool useTsa = ChkUseTsa.IsChecked == true;
                    byte[] signedData = DigitalSignatureEngine.SignCAdES(
                        TxtSignInput.Text,
                        signerCert,
                        useTsa,
                        TxtTsaUrl.Text);

                    File.WriteAllBytes(outputPath, signedData);

                    SetStatus($"Ký CAdES/CMS thành công: {outputPath}");
                    MessageBox.Show("Ký số CAdES/CMS thành công.", "Thành công", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else if (selectedIndex == 1)
                {
                    string outputPath = PickSaveFile(
                        "Lưu file PDF đã ký mô phỏng",
                        "PDF file (*.pdf)|*.pdf|All files (*.*)|*.*",
                        Path.GetFileNameWithoutExtension(TxtSignInput.Text) + ".signed.pdf");

                    if (string.IsNullOrWhiteSpace(outputPath))
                        return;

                    string location = $"Page={TxtPdfPage.Text}, X={TxtPdfX.Text}, Y={TxtPdfY.Text}, Size={TxtPdfSize.Text}";
                    string result = DigitalSignatureEngine.SignPAdESMock(TxtSignInput.Text, outputPath, signerCert, location);

                    SetStatus(result);
                    MessageBox.Show(result, "PAdES Mock", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    string outputPath = PickSaveFile(
                        "Lưu file XML đã ký",
                        "XML file (*.xml)|*.xml|All files (*.*)|*.*",
                        Path.GetFileNameWithoutExtension(TxtSignInput.Text) + ".signed.xml");

                    if (string.IsNullOrWhiteSpace(outputPath))
                        return;

                    DigitalSignatureEngine.SignXAdES(TxtSignInput.Text, outputPath, signerCert);

                    SetStatus($"Ký XAdES/XML thành công: {outputPath}");
                    MessageBox.Show("Ký số XML thành công.", "Thành công", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                ShowError(ex);
            }
        }

        private void BtnExecuteVerify_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                EnsureFileSelected(TxtVerifyInput.Text, "Vui lòng chọn file chữ ký cần xác thực.");

                string tsTime;
                bool isIntegrityOk;
                bool isChainOk;

                string details = DigitalSignatureEngine.VerifySignature(
                    TxtVerifyInput.Text,
                    out isIntegrityOk,
                    out isChainOk,
                    out tsTime);

                TxtResultIntegrity.Text = isIntegrityOk ? "HỢP LỆ" : "KHÔNG HỢP LỆ";
                TxtResultIntegrity.Foreground = isIntegrityOk ? Brushes.Green : Brushes.Red;

                TxtResultChain.Text = isChainOk ? "TIN CẬY" : "KHÔNG TIN CẬY";
                TxtResultChain.Foreground = isChainOk ? Brushes.Green : Brushes.Red;

                TxtResultTimestamp.Text = tsTime;
                TxtResultTimestamp.Foreground = tsTime.StartsWith("Có") ? Brushes.Green : Brushes.Gray;

                TxtVerifyDetails.Text = details;

                SetStatus("Đã kiểm tra chữ ký.");
            }
            catch (Exception ex)
            {
                ShowError(ex);
            }
        }

        private void BtnRefreshStore_Click(object sender, RoutedEventArgs e)
        {
            RefreshCertificateStore();
        }

        private void ComboSignType_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (GroupPdfSettings == null)
                return;

            GroupPdfSettings.Visibility = ComboSignType.SelectedIndex == 1
                ? Visibility.Visible
                : Visibility.Collapsed;
        }

        private void RefreshCertificateStore()
        {
            try
            {
                GridWindowsCerts.ItemsSource = CertProvider.GetCertificatesFromWindowsStore();
                SetStatus("Đã tải danh sách chứng thư từ Windows Store.");
            }
            catch (Exception ex)
            {
                ShowError(ex);
            }
        }

        private static string PickOpenFile(string filter)
        {
            OpenFileDialog dialog = new OpenFileDialog
            {
                Filter = filter,
                CheckFileExists = true
            };

            return dialog.ShowDialog() == true ? dialog.FileName : string.Empty;
        }

        private static string PickSaveFile(string title, string filter, string defaultFileName)
        {
            SaveFileDialog dialog = new SaveFileDialog
            {
                Title = title,
                Filter = filter,
                FileName = defaultFileName,
                AddExtension = true,
                OverwritePrompt = true
            };

            return dialog.ShowDialog() == true ? dialog.FileName : string.Empty;
        }

        private static void EnsureFileSelected(string path, string message)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                throw new InvalidOperationException(message);
        }

        private static string RemoveKnownExtension(string fileName, string extension)
        {
            if (fileName.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
                return fileName.Substring(0, fileName.Length - extension.Length);

            return Path.GetFileNameWithoutExtension(fileName) + ".decrypted" + Path.GetExtension(fileName);
        }

        private void SetStatus(string message)
        {
            TxtStatus.Text = "Trạng thái: " + message;
        }

        private void ShowError(Exception ex)
        {
            SetStatus("Lỗi: " + ex.Message);
            MessageBox.Show(ex.Message, "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
