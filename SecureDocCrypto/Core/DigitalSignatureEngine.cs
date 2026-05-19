#nullable disable
using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace SecureDocCrypto.Core
{
    public static class DigitalSignatureEngine
    {
        #region 1. CÁC HÀM KÝ SỐ (SIGNING)

        /// <summary>
        /// CAdES/CMS: ký số cho file bất kỳ. Kết quả trả về là dữ liệu CMS/PKCS#7.
        /// </summary>
        public static byte[] SignCAdES(string filePath, X509Certificate2 signerCert, bool useTimestamp, string tsaUrl)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentException("Đường dẫn file ký không hợp lệ.", nameof(filePath));

            if (signerCert == null)
                throw new ArgumentNullException(nameof(signerCert));

            if (!signerCert.HasPrivateKey)
                throw new InvalidOperationException("Chứng thư ký số phải chứa Private Key.");

            byte[] fileData = File.ReadAllBytes(filePath);
            ContentInfo contentInfo = new ContentInfo(fileData);

            SignedCms signedCms = new SignedCms(contentInfo, detached: false);

            CmsSigner cmsSigner = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, signerCert)
            {
                DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1") // SHA-256
            };

            signedCms.ComputeSignature(cmsSigner);

            if (useTimestamp && !string.IsNullOrWhiteSpace(tsaUrl))
            {
                try
                {
                    SignWithTimestamp(signedCms, tsaUrl);
                }
                catch (Exception ex)
                {
                    throw new Exception($"Lỗi tích hợp nhãn thời gian TSA: {ex.Message}", ex);
                }
            }

            return signedCms.Encode();
        }

        /// <summary>
        /// XAdES mô phỏng: ký XML dạng enveloped XML Signature.
        /// </summary>
        public static void SignXAdES(string inputXmlPath, string outputXmlPath, X509Certificate2 signerCert)
        {
            if (signerCert == null)
                throw new ArgumentNullException(nameof(signerCert));

            if (!signerCert.HasPrivateKey)
                throw new InvalidOperationException("Chứng thư ký số phải chứa Private Key.");

            XmlDocument xmlDoc = new XmlDocument
            {
                PreserveWhitespace = true
            };
            xmlDoc.Load(inputXmlPath);

            SignedXml signedXml = new SignedXml(xmlDoc)
            {
                SigningKey = signerCert.GetRSAPrivateKey()
            };

            Reference reference = new Reference
            {
                Uri = ""
            };

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);

            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(signerCert));
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature();

            XmlElement xmlDigitalSignature = signedXml.GetXml();
            if (xmlDoc.DocumentElement != null)
            {
                xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
            }

            xmlDoc.Save(outputXmlPath);
        }

        /// <summary>
        /// PAdES mock: hiện tại chỉ copy PDF để mô phỏng luồng ký.
        /// Muốn ký PAdES thật cần thư viện PDF signing như iText/BouncyCastle.
        /// </summary>
        public static string SignPAdESMock(string inputPdfPath, string outputPdfPath, X509Certificate2 cert, string location)
        {
            if (cert == null)
                throw new ArgumentNullException(nameof(cert));

            File.Copy(inputPdfPath, outputPdfPath, overwrite: true);
            return $"[PAdES Mock] Đã mô phỏng chèn chữ ký số của {cert.Subject} vào file PDF. Vị trí hiển thị: {location}";
        }

        /// <summary>
        /// Tích hợp RFC 3161 timestamp token vào UnsignedAttributes của SignerInfo.
        /// Lưu ý: API .NET dùng tham số requestSignerCertificates, không phải requestSignerCertificate.
        /// </summary>
        private static void SignWithTimestamp(SignedCms signedCms, string tsaUrl)
        {
            if (signedCms == null)
                throw new ArgumentNullException(nameof(signedCms));

            if (signedCms.SignerInfos.Count == 0)
                throw new InvalidOperationException("CMS chưa có chữ ký để đóng dấu thời gian.");

            SignerInfo signerInfo = signedCms.SignerInfos[0];

            Rfc3161TimestampRequest request =
                Rfc3161TimestampRequest.CreateFromSignerInfo(
                    signerInfo,
                    HashAlgorithmName.SHA256,
                    requestedPolicyId: null,
                    nonce: null,
                    requestSignerCertificates: true,
                    extensions: null);

            byte[] encodedRequest = request.Encode();

            using HttpClient client = new HttpClient();
            using ByteArrayContent content = new ByteArrayContent(encodedRequest);

            content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query");

            using HttpResponseMessage response = client.PostAsync(tsaUrl, content).GetAwaiter().GetResult();

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"Máy chủ TSA trả về HTTP {(int)response.StatusCode} - {response.ReasonPhrase}");
            }

            byte[] responseBytes = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();

            Rfc3161TimestampToken timestampToken =
                request.ProcessResponse(responseBytes, out _);

            byte[] timestampTokenBytes = timestampToken.AsSignedCms().Encode();

            // OID id-aa-signatureTimeStampToken
            AsnEncodedData timestampAttribute =
                new AsnEncodedData("1.2.840.113549.1.9.16.2.14", timestampTokenBytes);

            signerInfo.AddUnsignedAttribute(timestampAttribute);
        }

        #endregion

        #region 2. HÀM THẨM ĐỊNH & XÁC THỰC (VERIFICATION)

        public static string VerifySignature(string filePath, out bool isIntegrityOk, out bool isChainOk, out string tsTime)
        {
            isIntegrityOk = false;
            isChainOk = false;
            tsTime = "Không có nhãn thời gian";

            StringBuilder log = new StringBuilder();

            try
            {
                byte[] signedData = File.ReadAllBytes(filePath);
                SignedCms signedCms = new SignedCms();

                signedCms.Decode(signedData);

                log.AppendLine("--- KẾT QUẢ PHÂN TÍCH CHỮ KÝ CAdES/CMS ---");
                log.AppendLine($"Số lượng chữ ký tìm thấy: {signedCms.SignerInfos.Count}");

                foreach (SignerInfo signerInfo in signedCms.SignerInfos)
                {
                    log.AppendLine($"Người ký (Subject): {signerInfo.Certificate?.Subject}");
                    log.AppendLine($"Thuật toán băm: {signerInfo.DigestAlgorithm.FriendlyName}");

                    try
                    {
                        signerInfo.CheckSignature(verifySignatureOnly: true);
                        isIntegrityOk = true;
                        log.AppendLine("Tính toàn vẹn: HỢP LỆ.");
                    }
                    catch (Exception ex)
                    {
                        isIntegrityOk = false;
                        log.AppendLine($"Tính toàn vẹn: THẤT BẠI. {ex.Message}");
                    }

                    log.AppendLine();
                    log.AppendLine("--- PHÂN TÍCH CHUỖI CHỨNG CHỈ ---");

                    if (signerInfo.Certificate == null)
                    {
                        isChainOk = false;
                        log.AppendLine("Không tìm thấy chứng thư của người ký trong gói chữ ký.");
                    }
                    else
                    {
                        using X509Chain chain = new X509Chain();
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

                        isChainOk = chain.Build(signerInfo.Certificate);

                        foreach (X509ChainElement element in chain.ChainElements)
                        {
                            log.AppendLine($" -> Cấp bậc: {element.Certificate.Subject}");
                            log.AppendLine($"    Hiệu lực: {element.Certificate.NotBefore:dd/MM/yyyy} - {element.Certificate.NotAfter:dd/MM/yyyy}");

                            foreach (X509ChainStatus status in element.ChainElementStatus)
                            {
                                log.AppendLine($"    Trạng thái: {status.StatusInformation?.Trim()}");
                            }
                        }

                        log.AppendLine(isChainOk
                            ? "Chuỗi chứng chỉ: HỢP LỆ."
                            : "Chuỗi chứng chỉ: KHÔNG TIN CẬY / HẾT HẠN / BỊ THU HỒI / TỰ KÝ.");
                    }

                    foreach (CryptographicAttributeObject attr in signerInfo.UnsignedAttributes)
                    {
                        if (attr.Oid?.Value == "1.2.840.113549.1.9.16.2.14")
                        {
                            tsTime = "Có RFC 3161 timestamp token trong chữ ký.";
                            log.AppendLine($"Nhãn thời gian: {tsTime}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                log.AppendLine($"Lỗi phân tích cấu trúc chữ ký: {ex.Message}");
            }

            return log.ToString();
        }

        #endregion
    }
}
