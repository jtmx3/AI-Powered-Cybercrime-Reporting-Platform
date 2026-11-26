using System.Security.Cryptography;
using System.Text;
using ACCP.Application.Security;

namespace ACCP.Infrastructure.Security;

/// <summary>
/// AES-256-GCM authenticated encryption at rest.
/// - Binary envelope format: [8-byte magic "WATHIQE1"][12-byte nonce][16-byte tag][ciphertext]
/// - String envelope format: "enc:v1:" + Base64([12-byte nonce][16-byte tag][ciphertext])
/// Uses HKDF purpose-bound 256-bit keys and associated data (AAD) so ciphertext from one
/// domain purpose cannot be transplanted into another.
/// </summary>
public sealed class AesGcmDataEncryptionService : IDataEncryptionService
{
    public const string EvidenceFilePurpose = "evidence-file-at-rest";
    public const string DatabaseFieldPurpose = "database-field-at-rest";

    private static readonly byte[] BinaryMagic = Encoding.ASCII.GetBytes("WATHIQE1");
    private const string StringPrefix = "enc:v1:";
    private const int NonceSize = 12; // 96-bit standard GCM nonce
    private const int TagSize = 16;   // 128-bit GCM authentication tag

    private readonly ISecretKeyProvider _keyProvider;

    public AesGcmDataEncryptionService(ISecretKeyProvider keyProvider)
    {
        _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
    }

    public bool IsEncryptedPayload(ReadOnlySpan<byte> payload) =>
        payload.Length >= BinaryMagic.Length + NonceSize + TagSize &&
        payload[..BinaryMagic.Length].SequenceEqual(BinaryMagic);

    public byte[] EncryptBytes(ReadOnlySpan<byte> plaintext, string purpose)
    {
        var key = _keyProvider.DeriveKey(purpose, 32);
        try
        {
            var aad = Encoding.UTF8.GetBytes(purpose.Trim());
            var output = new byte[BinaryMagic.Length + NonceSize + TagSize + plaintext.Length];

            BinaryMagic.CopyTo(output, 0);
            var nonceSpan = output.AsSpan(BinaryMagic.Length, NonceSize);
            var tagSpan = output.AsSpan(BinaryMagic.Length + NonceSize, TagSize);
            var cipherSpan = output.AsSpan(BinaryMagic.Length + NonceSize + TagSize);

            RandomNumberGenerator.Fill(nonceSpan);

            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonceSpan, plaintext, cipherSpan, tagSpan, aad);

            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public byte[] DecryptBytes(ReadOnlySpan<byte> payload, string purpose)
    {
        if (!IsEncryptedPayload(payload))
        {
            // Backward-compatible read for legacy unencrypted files stored prior to hardening.
            return payload.ToArray();
        }

        var key = _keyProvider.DeriveKey(purpose, 32);
        try
        {
            var aad = Encoding.UTF8.GetBytes(purpose.Trim());
            var nonceSpan = payload.Slice(BinaryMagic.Length, NonceSize);
            var tagSpan = payload.Slice(BinaryMagic.Length + NonceSize, TagSize);
            var cipherSpan = payload[(BinaryMagic.Length + NonceSize + TagSize)..];

            var plaintext = new byte[cipherSpan.Length];
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonceSpan, cipherSpan, tagSpan, plaintext, aad);

            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public bool IsEncryptedString(string? value) =>
        !string.IsNullOrEmpty(value) &&
        value.StartsWith(StringPrefix, StringComparison.Ordinal);

    public string EncryptString(string plaintext, string purpose)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        if (IsEncryptedString(plaintext))
        {
            return plaintext;
        }

        var key = _keyProvider.DeriveKey(purpose, 32);
        try
        {
            var aad = Encoding.UTF8.GetBytes(purpose.Trim());
            var plainBytes = Encoding.UTF8.GetBytes(plaintext);
            var envelope = new byte[NonceSize + TagSize + plainBytes.Length];

            var nonceSpan = envelope.AsSpan(0, NonceSize);
            var tagSpan = envelope.AsSpan(NonceSize, TagSize);
            var cipherSpan = envelope.AsSpan(NonceSize + TagSize);

            RandomNumberGenerator.Fill(nonceSpan);

            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonceSpan, plainBytes, cipherSpan, tagSpan, aad);

            return StringPrefix + Convert.ToBase64String(envelope);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public string DecryptString(string value, string purpose)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (!IsEncryptedString(value))
        {
            // Backward-compatible read for pre-existing plaintext rows.
            return value;
        }

        var raw = Convert.FromBase64String(value[StringPrefix.Length..]);
        if (raw.Length < NonceSize + TagSize)
        {
            throw new CryptographicException("Encrypted string payload is malformed.");
        }

        var key = _keyProvider.DeriveKey(purpose, 32);
        try
        {
            var aad = Encoding.UTF8.GetBytes(purpose.Trim());
            var nonceSpan = raw.AsSpan(0, NonceSize);
            var tagSpan = raw.AsSpan(NonceSize, TagSize);
            var cipherSpan = raw.AsSpan(NonceSize + TagSize);

            var plainBytes = new byte[cipherSpan.Length];
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonceSpan, cipherSpan, tagSpan, plainBytes, aad);

            return Encoding.UTF8.GetString(plainBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
