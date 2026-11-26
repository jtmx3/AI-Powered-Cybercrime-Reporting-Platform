using System.Security.Cryptography;
using System.Text;
using ACCP.Infrastructure.Identity;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace ACCP.Infrastructure.Security;

/// <summary>
/// OWASP-compliant Argon2id password hasher (RFC 9106) for ASP.NET Core Identity.
/// Supports seamless verification and automatic upgrade (SuccessRehashNeeded) of
/// legacy PBKDF2 hashes already stored in the database.
/// </summary>
public sealed class Argon2idPasswordHasher : IPasswordHasher<ApplicationUser>
{
    private const string Prefix = "$argon2id$v=19$";
    private const int SaltSize = 16;          // 128-bit random salt
    private const int HashSize = 32;          // 256-bit output hash
    private const int MemorySizeKiB = 65536;  // 64 MiB (OWASP recommended)
    private const int Iterations = 3;         // 3 passes
    private const int DegreeOfParallelism = 2;

    private readonly PasswordHasher<ApplicationUser> _legacyFallback = new();

    public string HashPassword(ApplicationUser user, string password)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = ComputeArgon2id(password, salt, MemorySizeKiB, Iterations, DegreeOfParallelism, HashSize);

        try
        {
            return $"{Prefix}m={MemorySizeKiB},t={Iterations},p={DegreeOfParallelism}$" +
                   $"{Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    public PasswordVerificationResult VerifyHashedPassword(
        ApplicationUser user,
        string hashedPassword,
        string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(user);

        if (string.IsNullOrWhiteSpace(hashedPassword) || string.IsNullOrEmpty(providedPassword))
        {
            return PasswordVerificationResult.Failed;
        }

        if (!hashedPassword.StartsWith(Prefix, StringComparison.Ordinal))
        {
            // Verify legacy ASP.NET Identity PBKDF2 hash and signal Identity to rehash with Argon2id.
            var legacyResult = _legacyFallback.VerifyHashedPassword(user, hashedPassword, providedPassword);
            return legacyResult is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded
                ? PasswordVerificationResult.SuccessRehashNeeded
                : PasswordVerificationResult.Failed;
        }

        if (!TryParseHash(hashedPassword, out var memoryKiB, out var iterations, out var parallelism, out var salt, out var expectedHash))
        {
            return PasswordVerificationResult.Failed;
        }

        var computed = ComputeArgon2id(providedPassword, salt, memoryKiB, iterations, parallelism, expectedHash.Length);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(computed, expectedHash))
            {
                return PasswordVerificationResult.Failed;
            }

            var needsRehash = memoryKiB < MemorySizeKiB ||
                              iterations < Iterations ||
                              parallelism < DegreeOfParallelism ||
                              expectedHash.Length < HashSize;

            return needsRehash
                ? PasswordVerificationResult.SuccessRehashNeeded
                : PasswordVerificationResult.Success;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computed);
        }
    }

    private static byte[] ComputeArgon2id(
        string password,
        byte[] salt,
        int memoryKiB,
        int iterations,
        int parallelism,
        int hashLength)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                MemorySize = memoryKiB,
                Iterations = iterations,
                DegreeOfParallelism = parallelism
            };

            return argon2.GetBytes(hashLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static bool TryParseHash(
        string encoded,
        out int memoryKiB,
        out int iterations,
        out int parallelism,
        out byte[] salt,
        out byte[] hash)
    {
        memoryKiB = 0;
        iterations = 0;
        parallelism = 0;
        salt = [];
        hash = [];

        // Expected: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
        var parts = encoded.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 5 ||
            !string.Equals(parts[0], "argon2id", StringComparison.Ordinal) ||
            !string.Equals(parts[1], "v=19", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var param in parts[2].Split(','))
        {
            var kv = param.Split('=', 2);
            if (kv.Length != 2 || !int.TryParse(kv[1], out var val))
            {
                return false;
            }

            switch (kv[0])
            {
                case "m": memoryKiB = val; break;
                case "t": iterations = val; break;
                case "p": parallelism = val; break;
                default: return false;
            }
        }

        // Guard against parameter-based DoS from malformed/tampered hash strings.
        if (memoryKiB is < 8192 or > 524288 ||
            iterations is < 1 or > 20 ||
            parallelism is < 1 or > 16)
        {
            return false;
        }

        try
        {
            salt = Convert.FromBase64String(parts[3]);
            hash = Convert.FromBase64String(parts[4]);
            return salt.Length is >= 8 and <= 64 && hash.Length is >= 16 and <= 128;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
