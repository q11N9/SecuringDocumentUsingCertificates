# Securing Document Using Certificates

## Description

**Securing Document Using Certificates** is a C# desktop application used to encrypt, decrypt, digitally sign, and verify documents using digital certificates.

The application supports working with X.509 certificates and is designed for securing documents through public key cryptography.

## Main Features

- Encrypt documents using a recipient's public certificate
- Decrypt encrypted documents using a private certificate
- Digitally sign documents
- Verify digital signatures
- View certificates from the Windows Certificate Store

## Technologies Used

- C#
- .NET 8
- WPF
- X.509 Digital Certificates
- CMS / PKCS#7
- BouncyCastle

## Requirements

Before running the project, make sure you have installed:

- Visual Studio 2022 or later
- .NET 8 SDK
- Desktop development with C# workload in Visual Studio

## How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/q11N9/SecuringDocumentUsingCertificates.git
```

### 2. Open the Project

Open the cloned project folder with **Visual Studio**.

Make sure the project targets **.NET 8**.

### 3. Install Required NuGet Packages

In Visual Studio, open:

```text
Tools > NuGet Package Manager > Package Manager Console
```

Then run the following commands:

```powershell
Install-Package System.Security.Cryptography.Pkcs
Install-Package BouncyCastle.Cryptography
Install-Package System.Security.Cryptography.Xml
```

### 4. Build the Solution

In Visual Studio, select:

```text
Build > Build Solution
```

or press:

```text
Ctrl + Shift + B
```

### 5. Run the Application

After building successfully, you can run the application directly from Visual Studio.

You can also run the compiled `.exe` file from:

```text
bin/Release/
```

or:

```text
bin/Debug/
```

depending on your selected build configuration.

## Certificate Usage

The application works with common certificate formats such as:

```text
.cer
.crt
.pfx
.p12
```

Public certificates are used for encryption, while private certificates are required for decryption and digital signing.

## Notes

- Make sure the certificate used for decryption contains a private key.
- If you use a `.pfx` or `.p12` certificate, you may need to provide its password.
- Some signing or verification features may require trusted certificates installed in the Windows Certificate Store.

## Project Purpose

This project was developed for researching and demonstrating how digital certificates can be used to secure documents through encryption, decryption, digital signatures, and signature verification.
