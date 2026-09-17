// <file>
// <summary>
// Plugin metadata, signature verification, and trust management. Defines PluginInfo
// (assembly path, name, version, trust status, load state), PluginSignatureStatus
// (Official/ThirdParty/Unsigned/Invalid), and PluginTrustLevel (Trusted/Blocked/Unknown).
// Includes Authenticode signature verification for plugin DLLs.
// </summary>
// </file>

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Nexus.UI.Plugins;

/// <summary>
/// Signature verification status for a plugin.
/// </summary>
public enum PluginSignatureStatus
{
    /// <summary>
    /// Plugin is signed by the official Nexus Sentinel certificate.
    /// </summary>
    TrustedNexus,

    /// <summary>
    /// Plugin is signed but by a different certificate.
    /// </summary>
    SignedOther,

    /// <summary>
    /// Plugin signature is invalid (file was modified after signing).
    /// </summary>
    Invalid,

    /// <summary>
    /// Plugin is not signed.
    /// </summary>
    Unsigned,

    /// <summary>
    /// Error occurred while checking signature.
    /// </summary>
    Error
}

/// <summary>
/// Trust status for loading a plugin.
/// </summary>
public enum PluginTrustStatus
{
    /// <summary>
    /// Plugin is trusted (official Nexus signature).
    /// </summary>
    Trusted,

    /// <summary>
    /// Plugin is user-approved via whitelist.
    /// </summary>
    UserApproved,

    /// <summary>
    /// Plugin requires user approval to load.
    /// </summary>
    RequiresApproval,

    /// <summary>
    /// Plugin is blocked from loading.
    /// </summary>
    Blocked
}

/// <summary>
/// Information about a loaded or discovered plugin.
/// </summary>
public class PluginInfo
{
    /// <summary>
    /// Full path to the plugin DLL.
    /// </summary>
    public string FilePath { get; init; } = "";

    /// <summary>
    /// File name without path.
    /// </summary>
    public string FileName => Path.GetFileName(FilePath);

    /// <summary>
    /// SHA256 hash of the plugin file.
    /// </summary>
    public string FileHash { get; init; } = "";

    /// <summary>
    /// Signature verification status.
    /// </summary>
    public PluginSignatureStatus SignatureStatus { get; init; }

    /// <summary>
    /// Signer common name if signed, null otherwise.
    /// </summary>
    public string? SignerName { get; init; }

    /// <summary>
    /// Certificate thumbprint if signed, null otherwise.
    /// </summary>
    public string? CertificateThumbprint { get; init; }

    /// <summary>
    /// Trust status for loading.
    /// </summary>
    public PluginTrustStatus TrustStatus { get; set; }

    /// <summary>
    /// The loaded plugin instance, if loaded.
    /// </summary>
    public IPlugin? Instance { get; set; }

    /// <summary>
    /// Whether the plugin is currently loaded.
    /// </summary>
    public bool IsLoaded => Instance != null;

    /// <summary>
    /// Error message if loading failed.
    /// </summary>
    public string? LoadError { get; set; }

    /// <summary>
    /// Plugin metadata (populated after loading).
    /// </summary>
    public string? Id => Instance?.Id;
    public string? Name => Instance?.Name;
    public string? Version => Instance?.Version;
    public string? Author => Instance?.Author;
    public string? Description => Instance?.Description;

    /// <summary>
    /// Get a display-friendly signature status string.
    /// </summary>
    public string SignatureStatusDisplay => SignatureStatus switch
    {
        PluginSignatureStatus.TrustedNexus => $"Signed by Nexus Sentinel",
        PluginSignatureStatus.SignedOther => $"Signed by {SignerName ?? "Unknown"}",
        PluginSignatureStatus.Invalid => "Invalid Signature (TAMPERED)",
        PluginSignatureStatus.Unsigned => "Unsigned",
        PluginSignatureStatus.Error => "Signature Check Failed",
        _ => "Unknown"
    };

    /// <summary>
    /// Get a display-friendly trust status string.
    /// </summary>
    public string TrustStatusDisplay => TrustStatus switch
    {
        PluginTrustStatus.Trusted => "Trusted (Official)",
        PluginTrustStatus.UserApproved => "User Approved",
        PluginTrustStatus.RequiresApproval => "Requires Approval",
        PluginTrustStatus.Blocked => "Blocked",
        _ => "Unknown"
    };

    /// <summary>
    /// Calculate SHA256 hash of a file.
    /// </summary>
    public static string CalculateFileHash(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hashBytes = sha256.ComputeHash(stream);
        return Convert.ToHexString(hashBytes);
    }

    /// <summary>
    /// Check the signature status of a DLL file.
    /// </summary>
    public static (PluginSignatureStatus Status, string? SignerName, string? Thumbprint) CheckSignature(string filePath, string trustedThumbprint)
    {
        try
        {
            // Use WinVerifyTrust for Authenticode verification
            var (isValid, cert) = VerifyAuthenticodeSignature(filePath);

            if (cert == null)
            {
                return (PluginSignatureStatus.Unsigned, null, null);
            }

            var thumbprint = cert.Thumbprint;
            var signerName = cert.GetNameInfo(X509NameType.SimpleName, false);

            if (!isValid)
            {
                return (PluginSignatureStatus.Invalid, signerName, thumbprint);
            }

            // Check if it's the trusted Nexus certificate (only if thumbprint is configured)
            if (!string.IsNullOrEmpty(trustedThumbprint) &&
                string.Equals(thumbprint, trustedThumbprint, StringComparison.OrdinalIgnoreCase))
            {
                return (PluginSignatureStatus.TrustedNexus, signerName, thumbprint);
            }
            else
            {
                return (PluginSignatureStatus.SignedOther, signerName, thumbprint);
            }
        }
        catch (Exception)
        {
            return (PluginSignatureStatus.Error, null, null);
        }
    }

    /// <summary>
    /// Verify Authenticode signature using WinVerifyTrust.
    /// </summary>
    private static (bool IsValid, X509Certificate2? Certificate) VerifyAuthenticodeSignature(string filePath)
    {
        // First verify the signature using WinVerifyTrust
        bool isValid = WinTrustVerify(filePath);

        // Then try to extract the certificate
        var cert = GetSigningCertificate(filePath);

        return (isValid && cert != null, cert);
    }

    /// <summary>
    /// Extract signing certificate from an Authenticode-signed file.
    /// </summary>
    private static X509Certificate2? GetSigningCertificate(string filePath)
    {
        IntPtr hStore = IntPtr.Zero;
        IntPtr hMsg = IntPtr.Zero;
        IntPtr pCertContext = IntPtr.Zero;

        try
        {
            // Query the certificate from the signed file
            if (!CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                filePath,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                out _,
                out _,
                out _,
                ref hStore,
                ref hMsg,
                ref pCertContext))
            {
                return null;
            }

            // Get signer info size
            int signerInfoSize = 0;
            CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, IntPtr.Zero, ref signerInfoSize);
            if (signerInfoSize == 0)
            {
                return null;
            }

            // Get signer info
            IntPtr signerInfoPtr = Marshal.AllocHGlobal(signerInfoSize);
            try
            {
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfoPtr, ref signerInfoSize))
                {
                    return null;
                }

                var signerInfo = Marshal.PtrToStructure<CMSG_SIGNER_INFO>(signerInfoPtr);

                // Find certificate in store
                var certInfo = new CERT_INFO
                {
                    Issuer = signerInfo.Issuer,
                    SerialNumber = signerInfo.SerialNumber
                };

                pCertContext = CertFindCertificateInStore(
                    hStore,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0,
                    CERT_FIND_SUBJECT_CERT,
                    ref certInfo,
                    IntPtr.Zero);

                if (pCertContext != IntPtr.Zero)
                {
                    return new X509Certificate2(pCertContext);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(signerInfoPtr);
            }

            return null;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (pCertContext != IntPtr.Zero)
                CertFreeCertificateContext(pCertContext);
            if (hStore != IntPtr.Zero)
                CertCloseStore(hStore, 0);
            if (hMsg != IntPtr.Zero)
                CryptMsgClose(hMsg);
        }
    }

    /// <summary>
    /// Verify file signature using WinVerifyTrust.
    /// </summary>
    private static bool WinTrustVerify(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        IntPtr fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WTD_SAFER_FLAG,
                dwUIContext = 0
            };

            var actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            int result = WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref trustData);

            // Close the state data
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref trustData);

            return result == 0; // ERROR_SUCCESS
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    #region WinTrust P/Invoke

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_SAFER_FLAG = 0x100;

    private const int CERT_QUERY_OBJECT_FILE = 1;
    private const int CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1024;
    private const int CERT_QUERY_FORMAT_FLAG_BINARY = 2;
    private const int CMSG_SIGNER_INFO_PARAM = 6;
    private const int CERT_FIND_SUBJECT_CERT = 720896;
    private const int X509_ASN_ENCODING = 1;
    private const int PKCS_7_ASN_ENCODING = 65536;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CRYPTOAPI_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CMSG_SIGNER_INFO
    {
        public int dwVersion;
        public CRYPTOAPI_BLOB Issuer;
        public CRYPTOAPI_BLOB SerialNumber;
        public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
        public CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
        public CRYPTOAPI_BLOB EncryptedHash;
        public CRYPT_ATTRIBUTES AuthAttrs;
        public CRYPT_ATTRIBUTES UnauthAttrs;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CRYPT_ALGORITHM_IDENTIFIER
    {
        public IntPtr pszObjId;
        public CRYPTOAPI_BLOB Parameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CRYPT_ATTRIBUTES
    {
        public int cAttr;
        public IntPtr rgAttr;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CERT_INFO
    {
        public int dwVersion;
        public CRYPTOAPI_BLOB SerialNumber;
        public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
        public CRYPTOAPI_BLOB Issuer;
        public long NotBefore;
        public long NotAfter;
        public CRYPTOAPI_BLOB Subject;
        public IntPtr SubjectPublicKeyInfo;
        public CRYPTOAPI_BLOB IssuerUniqueId;
        public CRYPTOAPI_BLOB SubjectUniqueId;
        public int cExtension;
        public IntPtr rgExtension;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptQueryObject(
        int dwObjectType,
        [MarshalAs(UnmanagedType.LPWStr)] string pvObject,
        int dwExpectedContentTypeFlags,
        int dwExpectedFormatTypeFlags,
        int dwFlags,
        out int pdwMsgAndCertEncodingType,
        out int pdwContentType,
        out int pdwFormatType,
        ref IntPtr phCertStore,
        ref IntPtr phMsg,
        ref IntPtr ppvContext);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptMsgGetParam(
        IntPtr hCryptMsg,
        int dwParamType,
        int dwIndex,
        IntPtr pvData,
        ref int pcbData);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern IntPtr CertFindCertificateInStore(
        IntPtr hCertStore,
        int dwCertEncodingType,
        int dwFindFlags,
        int dwFindType,
        ref CERT_INFO pvFindPara,
        IntPtr pPrevCertContext);

    [DllImport("crypt32.dll")]
    private static extern bool CertFreeCertificateContext(IntPtr pCertContext);

    [DllImport("crypt32.dll")]
    private static extern bool CertCloseStore(IntPtr hCertStore, int dwFlags);

    [DllImport("crypt32.dll")]
    private static extern bool CryptMsgClose(IntPtr hCryptMsg);

    #endregion
}

/// <summary>
/// Plugin trust settings persisted to disk.
/// </summary>
public class PluginTrustSettings
{
    /// <summary>
    /// The official Nexus Sentinel certificate thumbprint.
    /// This is embedded in the application and cannot be changed by users.
    /// TODO: Replace with actual thumbprint after creating the code-signing certificate.
    /// While this is a placeholder, no plugin will be auto-trusted as TrustedNexus;
    /// all plugins will require user approval or whitelist entry.
    /// </summary>
    public const string NexusCertificateThumbprint = "";

    /// <summary>
    /// Whether the certificate thumbprint has been configured.
    /// When false, TrustedNexus status is never granted (all plugins require approval).
    /// </summary>
    public static bool IsCertificateThumbprintConfigured =>
        !string.IsNullOrEmpty(NexusCertificateThumbprint) &&
        NexusCertificateThumbprint != "PLACEHOLDER_THUMBPRINT_UPDATE_AFTER_CREATING_CERT";

    /// <summary>
    /// Common name expected on the Nexus certificate.
    /// </summary>
    public const string NexusCertificateSubject = "CN=Nexus Sentinel";

    /// <summary>
    /// List of SHA256 hashes of user-approved unsigned/third-party plugins.
    /// </summary>
    public List<ApprovedPlugin> ApprovedPlugins { get; set; } = new();

    /// <summary>
    /// List of SHA256 hashes of blocked plugins.
    /// </summary>
    public List<string> BlockedHashes { get; set; } = new();

    /// <summary>
    /// Whether to prompt for approval or auto-block unknown plugins.
    /// </summary>
    public bool PromptForUnknown { get; set; } = true;

    /// <summary>
    /// Check if a plugin hash is approved.
    /// </summary>
    public bool IsApproved(string hash)
    {
        return ApprovedPlugins.Any(p =>
            string.Equals(p.Hash, hash, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Check if a plugin hash is blocked.
    /// </summary>
    public bool IsBlocked(string hash)
    {
        return BlockedHashes.Any(h =>
            string.Equals(h, hash, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Approve a plugin by hash.
    /// </summary>
    public void Approve(string hash, string fileName, string? pluginName = null)
    {
        if (!IsApproved(hash))
        {
            ApprovedPlugins.Add(new ApprovedPlugin
            {
                Hash = hash,
                FileName = fileName,
                PluginName = pluginName,
                ApprovedDate = DateTime.UtcNow
            });
        }
        // Remove from blocked if present
        BlockedHashes.RemoveAll(h => string.Equals(h, hash, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Block a plugin by hash.
    /// </summary>
    public void Block(string hash)
    {
        if (!IsBlocked(hash))
        {
            BlockedHashes.Add(hash);
        }
        // Remove from approved if present
        ApprovedPlugins.RemoveAll(p => string.Equals(p.Hash, hash, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Revoke approval for a plugin.
    /// </summary>
    public void RevokeApproval(string hash)
    {
        ApprovedPlugins.RemoveAll(p => string.Equals(p.Hash, hash, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>
/// Information about an approved plugin.
/// </summary>
public class ApprovedPlugin
{
    public string Hash { get; set; } = "";
    public string FileName { get; set; } = "";
    public string? PluginName { get; set; }
    public DateTime ApprovedDate { get; set; }
}
