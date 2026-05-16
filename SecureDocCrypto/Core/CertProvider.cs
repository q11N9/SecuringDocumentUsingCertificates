using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SecureDocCrypto.Core
{
    internal class CertProvider
    {
        /// <summary>
        /// Nạp chứng thư số chỉ chứa Public Key (Dùng để MÃ HÓA).
        /// Thường là các file có đuôi: .cer, .crt, .der
        /// </summary>
        public static X509Certificate2 LoadPublicKey(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("Không tìm thấy file chứng thư số!", filePath);

            try
            {
                // Nạp chứng thư cơ bản
                X509Certificate2 cert = new X509Certificate2(filePath);
                return cert;
            }
            catch (Exception ex)
            {
                throw new Exception($"Lỗi khi đọc file Public Key: {ex.Message}");
            }
        }

        /// <summary>
        /// Nạp chứng thư số chứa cả Private Key (Dùng để GIẢI MÃ hoặc KÝ SỐ).
        /// Thường là các file có đuôi: .pfx, .p12
        /// </summary>
        public static X509Certificate2 LoadPrivateKey(string filePath, string password)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("Không tìm thấy file chứng thư số!", filePath);

            try
            {
                // Nạp chứng thư với mật khẩu. 
                // Flag Exportable cho phép trích xuất Private Key vào bộ nhớ để giải mã
                X509Certificate2 cert = new X509Certificate2(
                    filePath,
                    password,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

                // Kiểm tra xem file này có thực sự chứa Private Key không
                if (!cert.HasPrivateKey)
                {
                    throw new Exception("File này chỉ chứa Public Key. Không thể dùng để giải mã!");
                }

                return cert;
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                throw new Exception("Mật khẩu giải mã chứng thư (Passphrase) không chính xác!");
            }
            catch (Exception ex)
            {
                throw new Exception($"Lỗi khi đọc file Private Key: {ex.Message}");
            }
        }

        /// <summary>
        /// (Nâng cao) Quét Windows Certificate Store để lấy danh sách các chứng thư đang cài trong máy
        /// Rất hữu ích khi người dùng cắm USB Token chữ ký số.
        /// </summary>
        public static List<X509Certificate2> GetCertificatesFromWindowsStore()
        {
            List<X509Certificate2> validCerts = new List<X509Certificate2>();

            // Mở kho chứa chứng thư cá nhân của User hiện tại
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                foreach (X509Certificate2 cert in store.Certificates)
                {
                    // Chỉ lấy những chứng thư chưa hết hạn
                    if (DateTime.Now >= cert.NotBefore && DateTime.Now <= cert.NotAfter)
                    {
                        validCerts.Add(cert);
                    }
                }
            }

            return validCerts;
        }
    }
}
