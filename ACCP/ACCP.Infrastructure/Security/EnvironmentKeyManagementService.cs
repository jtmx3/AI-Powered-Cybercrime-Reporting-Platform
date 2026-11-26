using System.Security.Cryptography;
using System.Text;
using ACCP.Application.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ACCP.Infrastructure.Security;

/// <summary>
/// KMS-ready key provider supporting environment variables, .NET User Secrets,
/// and externally injected secrets from HashiCorp Vault or Azure Key Vault.
/// Fails closed in Production if no 256-bit master key is configured.
/// </summary>
public sealed class EnvironmentKeyManagementService : ISecretKeyProvider, IDisposable
{
    public const string EnvironmentVariableName = "ACCP_DATA_ENCRYPTION_KEY";
    public const string ConfigurationKey = "Security:KeyManagement:MasterKeyBase64";

    private readonly byte[] _masterKey;
    public bool IsProductionKeyConfigured { get; }

    public EnvironmentKeyManagementService(
        IConfiguration configuration,
        IHostEnvironment environment,
        ILogger<EnvironmentKeyManagementService> logger)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(logger);

        var rawKey = Environment.GetEnvironmentVariable(EnvironmentVariableName)?.Trim();
        if (string.IsNullOrWhiteSpace(rawKey))
        {
            rawKey = configuration[ConfigurationKey]?.Trim();
        }

        if (!string.IsNullOrWhiteSpace(rawKey))
        {
            _masterKey = DecodeAndValidateMasterKey(rawKey);
            IsProductionKeyConfigured = true;
            return;
        }

        if (!environment.IsDevelopment())
        {
            throw new InvalidOperationException(
                $"Missing 256-bit master encryption key. Configure '{EnvironmentVariableName}' " +
                $"or '{ConfigurationKey}' via a KMS (HashiCorp Vault / Azure Key Vault) before running outside Development.");
        }

        // Development-only deterministic local key so local runs work without embedding
        // a production secret. Never used outside Development.
        var devSeed = Encoding.UTF8.GetBytes(
            $"WATHIQ-DEV-ONLY::{Environment.MachineName}::{environment.ContentRootPath}");
        _masterKey = SHA256.HashData(devSeed);
        IsProductionKeyConfigured = false;

        logger.LogWarning(
            "ACCP KMS: Using development-only fallback encryption key. Configure '{EnvVar}' or a KMS before production deployment.",
            EnvironmentVariableName);
    }

    /// <summary>
    /// Constructor for unit tests using an explicit 256-bit key.
    /// </summary>
    public EnvironmentKeyManagementService(byte[] masterKey)
    {
        if (masterKey is null || masterKey.Length < 32)
        {
            throw new ArgumentException("Master key must be at least 32 bytes (256 bits).", nameof(masterKey));
        }

        _masterKey = (byte[])masterKey.Clone();
        IsProductionKeyConfigured = true;
    }

    public byte[] DeriveKey(string purpose, int lengthBytes = 32)
    {
        if (string.IsNullOrWhiteSpace(purpose))
        {
            throw new ArgumentException("Key derivation purpose must be non-empty.", nameof(purpose));
        }

        if (lengthBytes is < 16 or > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(lengthBytes), "Derived key length must be between 16 and 64 bytes.");
        }

        var salt = Encoding.UTF8.GetBytes("WATHIQ.ACCP.KMS.HKDF.V1");
        var info = Encoding.UTF8.GetBytes(purpose.Trim());
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, _masterKey, lengthBytes, salt, info);
    }

    private static byte[] DecodeAndValidateMasterKey(string base64Key)
    {
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(base64Key);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException(
                "Master encryption key must be a valid Base64-encoded 256-bit (32-byte) key.", ex);
        }

        if (decoded.Length < 32)
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw new InvalidOperationException(
                "Master encryption key must be at least 32 bytes (256 bits).");
        }

        return decoded;
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_masterKey);
    }
}
