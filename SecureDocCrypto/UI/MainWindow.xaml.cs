using System;
using System.Windows;
using Microsoft.Win32;
using SecureDocCrypto.Core; // Khai báo để gọi các hàm mã hóa từ tầng Core

namespace SecureDocCrypto.UI
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            LoadWindowsCertificates(); // Tự động quét kho chứng thư khi mở ứng dụng
        }

        #region XỬ LÝ SỰ KIỆN TAB MÃ HÓA

        private void BtnBrowseEncryptInput_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.Title = "Chọn tài liệu cần mã hóa";
            if (dlg.ShowDialog() == true)
            {
                TxtEncryptInput.Text = dlg.FileName;
            }
        }

        private void BtnBrowsePublicKey_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.Filter = "Chứng thư số (*.cer;*.crt)|*.cer;*.crt|Tất cả các file (*.*)|*.*";
            if (dlg.ShowDialog() == true)
            {
                TxtPublicKeyPath.Text = dlg.FileName;
            }
        }

        private void BtnExecuteEncrypt_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(TxtEncryptInput.Text) || string.IsNullOrEmpty(TxtPublicKeyPath.Text))
            {
                MessageBox.Show("Vui lòng chọn đầy đủ File dữ liệu và Chứng thư số người nhận!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                TxtStatus.Text = "Trạng thái: Đang tiến hành mã hóa...";

                // 1. Nạp public key
                var publicKey = CertProvider.LoadPublicKey(TxtPublicKeyPath.Text);

                // 2. Định nghĩa file đầu ra (.p7m)
                string outputPath = TxtEncryptInput.Text + ".p7m";

                // 3. Gọi lõi mã hóa thực thi
                CryptoEngine.EncryptFile(TxtEncryptInput.Text, outputPath, publicKey);

                TxtStatus.Text = $"Trạng thái: Mã hóa thành công! File lưu tại: {outputPath}";
                MessageBox.Show($"Mã hóa tài liệu thành công!\nFile đầu ra: {outputPath}", "Thành công", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                TxtStatus.Text = "Trạng thái: Mã hóa thất bại.";
                MessageBox.Show(ex.Message, "Lỗi Hệ Thống", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        #region XỬ LÝ SỰ KIỆN TAB GIẢI MÃ

        private void BtnBrowseDecryptInput_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.Filter = "File đã mã hóa (*.p7m)|*.p7m";
            if (dlg.ShowDialog() == true)
            {
                TxtDecryptInput.Text = dlg.FileName;
            }
        }

        private void BtnBrowsePrivateKey_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.Filter = "Chứng thư cá nhân (*.pfx;*.p12)|*.pfx;*.p12";
            if (dlg.ShowDialog() == true)
            {
                TxtPrivateKeyPath.Text = dlg.FileName;
            }
        }

        private void BtnExecuteDecrypt_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(TxtDecryptInput.Text) || string.IsNullOrEmpty(TxtPrivateKeyPath.Text))
            {
                MessageBox.Show("Vui lòng chọn file mã hóa và file khóa cá nhân tương ứng!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                TxtStatus.Text = "Trạng thái: Đang thực hiện giải mã...";

                // 1. Nạp Private Key kèm mật khẩu
                var privateKey = CertProvider.LoadPrivateKey(TxtPrivateKeyPath.Text, TxtPrivateKeyPassword.Password);

                // 2. Tạo đường dẫn đầu ra
                string outputPath = TxtDecryptInput.Text.Replace(".p7m", "");
                if (outputPath == TxtDecryptInput.Text) outputPath += ".decrypted";

                // 3. Gọi lõi giải mã thực thi
                CryptoEngine.DecryptFile(TxtDecryptInput.Text, outputPath, privateKey);

                TxtStatus.Text = $"Trạng thái: Giải mã thành công! Đã khôi phục file.";
                MessageBox.Show($"Giải mã thành công! Tài liệu đã được khôi phục tại:\n{outputPath}", "Thành công", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                TxtStatus.Text = "Trạng thái: Giải mã thất bại.";
                MessageBox.Show(ex.Message, "Lỗi Hệ Thống", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        #region CHỨC NĂNG QUẢN LÝ KHO KEY WINDOWS

        private void LoadWindowsCertificates()
        {
            try
            {
                var certs = CertProvider.GetCertificatesFromWindowsStore();
                GridWindowsCerts.ItemsSource = certs;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Không thể quét kho khóa hệ thống: {ex.Message}", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void BtnRefreshStore_Click(object sender, RoutedEventArgs e)
        {
            LoadWindowsCertificates();
            MessageBox.Show("Đã làm mới danh sách chứng thư số từ Windows Certificate Store!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        #endregion

        #region ĐIỀU KHIỂN CỬA SỔ (WINDOW CONTROLS)

        // Hàm giúp người dùng giữ chuột trái vào thanh tiêu đề màu xanh để kéo dịch chuyển cửa sổ app
        private void Header_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (e.ChangedButton == System.Windows.Input.MouseButton.Left)
            {
                this.DragMove();
            }
        }

        // Xử lý nút Thu nhỏ xuống Taskbar (Minimize)
        private void BtnMinimize_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        // Xử lý nút Phóng to / Thu nhỏ về kích thước cũ (Maximize/Restore)
        private void BtnMaximize_Click(object sender, RoutedEventArgs e)
        {
            if (this.WindowState == WindowState.Maximized)
            {
                this.WindowState = WindowState.Normal;
            }
            else
            {
                this.WindowState = WindowState.Maximized;
            }
        }

        // Xử lý nút Đóng ứng dụng hoàn toàn (Close)
        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        #endregion
    }
}