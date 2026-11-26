namespace ACCP.Application.Security;

/// <summary>
/// Provides cryptographically isolated 256-bit encryption keys backed by an external
/// Key Management System (environment secrets, HashiCorp Vault, Azure Key Vault, etc.).
/// Master keys must never be hardcoded in source code.
/// </summary>
public interface ISecretKeyProvider
{
    /// <summary>
    /// Derives a purpose-specific 256-bit (32-byte) key using HKDF-SHA256
    /// so evidence files, database fields, and audit integrity never share raw key material.
    /// </summary>
    byte[] DeriveKey(string purpose, int lengthBytes = 32);

    /// <summary>
    /// Indicates whether the active key material comes from a configured KMS/secret store
    /// rather than an ephemeral development fallback.
    /// </summary>
    bool IsProductionKeyConfigured { get; }
}
