using System;
using System.IO;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace SecureDocCrypto.Core
{
    public static class CryptoEngine
    {
        /// <summary>
        /// MÃ HÓA tài liệu bất kỳ.
        /// Sử dụng Public Key của người nhận. Đầu ra thường có đuôi .p7m
        /// </summary>
        public static void EncryptFile(string inputFilePath, string outputFilePath, X509Certificate2 recipientCert)
        {
            try
            {
                // 1. Đọc toàn bộ file cần mã hóa thành mảng Byte
                byte[] fileData = File.ReadAllBytes(inputFilePath);

                // 2. Tạo đối tượng bọc dữ liệu theo chuẩn CMS
                ContentInfo contentInfo = new ContentInfo(fileData);
                EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo);

                // 3. Chỉ định người nhận (Sử dụng chứng thư số của họ)
                // Dùng SubjectIdentifierType.IssuerAndSerialNumber là chuẩn tương thích tốt nhất
                CmsRecipient recipient = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, recipientCert);

                // 4. Thực hiện mã hóa Lai (Hệ thống tự động sinh AES, mã hóa file, dùng RSA mã hóa khóa AES)
                envelopedCms.Encrypt(recipient);

                // 5. Đóng gói toàn bộ thành mảng byte chuẩn PKCS#7
                byte[] encryptedData = envelopedCms.Encode();

                // 6. Ghi ra file mới trên ổ cứng
                File.WriteAllBytes(outputFilePath, encryptedData);
            }
            catch (Exception ex)
            {
                throw new Exception($"Lỗi trong quá trình MÃ HÓA: {ex.Message}");
            }
        }

        /// <summary>
        /// GIẢI MÃ tài liệu.
        /// Yêu cầu phải có chứng thư chứa Private Key khớp với người nhận.
        /// </summary>
        public static void DecryptFile(string inputFilePath, string outputFilePath, X509Certificate2 myPrivateCert)
        {
            try
            {
                // 1. Đọc file đã bị mã hóa (.p7m) vào bộ nhớ
                byte[] encryptedData = File.ReadAllBytes(inputFilePath);

                // 2. Khởi tạo đối tượng CMS và giải mã cấu trúc file
                EnvelopedCms envelopedCms = new EnvelopedCms();
                envelopedCms.Decode(encryptedData);

                // 3. Đưa Private Key của mình vào một "bộ sưu tập" để hệ thống dùng
                X509Certificate2Collection certCollection = new X509Certificate2Collection(myPrivateCert);

                // 4. Giải mã! Hệ thống sẽ tự dùng Private Key khớp để mở khóa AES, sau đó giải mã dữ liệu
                envelopedCms.Decrypt(certCollection);

                // 5. Trích xuất mảng byte dữ liệu gốc đã được giải mã
                byte[] decryptedData = envelopedCms.ContentInfo.Content;

                // 6. Ghi dữ liệu trả lại thành file ban đầu
                File.WriteAllBytes(outputFilePath, decryptedData);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                throw new Exception("Lỗi: Không thể giải mã! Chứng thư số (Private Key) cung cấp không khớp hoặc file đã bị hỏng.");
            }
            catch (Exception ex)
            {
                throw new Exception($"Lỗi trong quá trình GIẢI MÃ: {ex.Message}");
            }
        }
    }
}