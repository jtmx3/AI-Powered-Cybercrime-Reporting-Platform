namespace ACCP.Application.Security;

/// <summary>
/// Authenticated AES-256-GCM encryption at rest for evidence files and sensitive database fields.
/// </summary>
public interface IDataEncryptionService
{
    byte[] EncryptBytes(ReadOnlySpan<byte> plaintext, string purpose);

    byte[] DecryptBytes(ReadOnlySpan<byte> payload, string purpose);

    bool IsEncryptedPayload(ReadOnlySpan<byte> payload);

    string EncryptString(string plaintext, string purpose);

    string DecryptString(string value, string purpose);

    bool IsEncryptedString(string? value);
}
