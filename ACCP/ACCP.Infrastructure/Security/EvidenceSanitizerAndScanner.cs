using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;
using ACCP.Application.Security;

namespace ACCP.Infrastructure.Security;

/// <summary>
/// Strips privacy-leaking metadata (EXIF/GPS/XMP/IPTC/comments) from PNG and JPEG evidence images,
/// validates structural integrity (IEND / EOI), and blocks dangerous active content inside PDFs.
/// </summary>
public static partial class EvidenceMetadataSanitizer
{
    private static readonly byte[] PngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    // Safe PNG chunks to retain: critical chunks + display geometry only.
    // Strips eXIf, tEXt, zTXt, iTXt, tIME, iCCP (device color profile fingerprinting),
    // and all unknown/private metadata chunks.
    private static readonly HashSet<string> AllowedPngChunks = new(StringComparer.Ordinal)
    {
        "IHDR", "PLTE", "IDAT", "IEND",
        "tRNS", "gAMA", "cHRM", "sRGB", "sBIT", "bKGD", "pHYs", "acTL", "fcTL", "fdAT"
    };

    public static byte[] SanitizeAndValidate(byte[] fileBytes, string extension)
    {
        return extension.ToLowerInvariant() switch
        {
            ".png" => SanitizePng(fileBytes),
            ".jpg" or ".jpeg" => SanitizeJpeg(fileBytes),
            ".pdf" => ValidatePdf(fileBytes),
            _ => throw new InvalidOperationException("نوع الملف غير مسموح أو محتواه لا يطابق امتداده.")
        };
    }

    public static byte[] SanitizePng(byte[] data)
    {
        if (data.Length < 33 || !data.AsSpan(0, 8).SequenceEqual(PngSignature))
        {
            throw new InvalidOperationException("ملف PNG غير صالح أو تالف.");
        }

        using var output = new MemoryStream(data.Length);
        output.Write(PngSignature, 0, PngSignature.Length);

        var offset = 8;
        var sawIhdr = false;
        var sawIdat = false;
        var sawIend = false;

        while (offset + 12 <= data.Length)
        {
            var chunkLength = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4));
            if (chunkLength > int.MaxValue || offset + 12L + chunkLength > data.Length)
            {
                throw new InvalidOperationException("بنية ملف PNG غير صالحة.");
            }

            var chunkType = Encoding.ASCII.GetString(data, offset + 4, 4);
            var totalChunkBytes = 12 + (int)chunkLength;

            if (chunkType == "IHDR") sawIhdr = true;
            if (chunkType == "IDAT") sawIdat = true;

            if (AllowedPngChunks.Contains(chunkType))
            {
                output.Write(data, offset, totalChunkBytes);
            }

            offset += totalChunkBytes;

            if (chunkType == "IEND")
            {
                sawIend = true;
                break;
            }
        }

        if (!sawIhdr || !sawIdat || !sawIend)
        {
            throw new InvalidOperationException("ملف PNG غير مكتمل أو غير صالح.");
        }

        // Trailing bytes after IEND (often used for polyglot/steganographic payloads) are discarded.
        return output.ToArray();
    }

    public static byte[] SanitizeJpeg(byte[] data)
    {
        if (data.Length < 4 || data[0] != 0xFF || data[1] != 0xD8)
        {
            throw new InvalidOperationException("ملف JPEG غير صالح أو تالف.");
        }

        using var output = new MemoryStream(data.Length);
        output.WriteByte(0xFF);
        output.WriteByte(0xD8);

        var offset = 2;
        var sawSos = false;
        var sawEoi = false;

        while (offset + 1 < data.Length)
        {
            if (data[offset] != 0xFF)
            {
                throw new InvalidOperationException("بنية ملف JPEG غير صالحة.");
            }

            // Skip fill 0xFF bytes.
            while (offset < data.Length && data[offset] == 0xFF)
            {
                offset++;
            }

            if (offset >= data.Length)
            {
                break;
            }

            var marker = data[offset++];

            // EOI (End of Image)
            if (marker == 0xD9)
            {
                output.WriteByte(0xFF);
                output.WriteByte(0xD9);
                sawEoi = true;
                break;
            }

            // Standalone markers without length (RST0-RST7, TEM)
            if (marker is >= 0xD0 and <= 0xD7 or 0x01)
            {
                output.WriteByte(0xFF);
                output.WriteByte(marker);
                continue;
            }

            if (offset + 2 > data.Length)
            {
                throw new InvalidOperationException("مقطع JPEG مقطوع بشكل غير صالح.");
            }

            var segmentLength = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset, 2));
            if (segmentLength < 2 || offset + segmentLength > data.Length)
            {
                throw new InvalidOperationException("طول مقطع JPEG غير صالح.");
            }

            // Strip APP1..APP15 (0xE1..0xEF: EXIF, GPS, XMP, IPTC, Adobe) and COM (0xFE: comments).
            // For APP0 (0xE0), retain only a clean 14-byte JFIF header without embedded thumbnail.
            bool isCleanJfifApp0 = marker == 0xE0 &&
                                   segmentLength == 16 &&
                                   offset + 7 <= data.Length &&
                                   data[offset + 2] == (byte)'J' &&
                                   data[offset + 3] == (byte)'F' &&
                                   data[offset + 4] == (byte)'I' &&
                                   data[offset + 5] == (byte)'F' &&
                                   data[offset + 6] == 0x00 &&
                                   data[offset + 14] == 0x00 &&
                                   data[offset + 15] == 0x00;

            var stripSegment = (marker is >= 0xE1 and <= 0xEF) ||
                               marker == 0xFE ||
                               (marker == 0xE0 && !isCleanJfifApp0);

            if (!stripSegment)
            {
                output.WriteByte(0xFF);
                output.WriteByte(marker);
                output.Write(data, offset, segmentLength);
            }

            offset += segmentLength;

            // Start of Scan (0xDA): copy entropy-coded scan bytes until EOI (0xFFD9).
            if (marker == 0xDA)
            {
                sawSos = true;
                var scanStart = offset;
                var foundEnd = false;

                while (offset + 1 < data.Length)
                {
                    if (data[offset] == 0xFF)
                    {
                        var next = data[offset + 1];
                        if (next == 0x00 || (next is >= 0xD0 and <= 0xD7))
                        {
                            offset += 2;
                            continue;
                        }

                        if (next == 0xD9)
                        {
                            output.Write(data, scanStart, offset - scanStart);
                            output.WriteByte(0xFF);
                            output.WriteByte(0xD9);
                            sawEoi = true;
                            foundEnd = true;
                            break;
                        }

                        // Another marker (e.g. progressive JPEG additional scan)
                        if (next != 0xFF)
                        {
                            output.Write(data, scanStart, offset - scanStart);
                            foundEnd = true;
                            break;
                        }
                    }

                    offset++;
                }

                if (!foundEnd)
                {
                    throw new InvalidOperationException("ملف JPEG لا ينتهي بعلامة نهاية صالحة.");
                }

                if (sawEoi)
                {
                    break;
                }
            }
        }

        if (!sawSos || !sawEoi)
        {
            throw new InvalidOperationException("ملف JPEG غير مكتمل أو لا يحتوي بيانات صورة صالحة.");
        }

        return output.ToArray();
    }

    public static byte[] ValidatePdf(byte[] data)
    {
        if (data.Length < 16 ||
            data[0] != 0x25 || data[1] != 0x50 || data[2] != 0x44 || data[3] != 0x46 || data[4] != 0x2D)
        {
            throw new InvalidOperationException("ملف PDF غير صالح.");
        }

        // Inspect ASCII/Latin1 structure for active scripting, auto-execution, or embedded executable payloads.
        var latin1 = Encoding.Latin1.GetString(data);

        if (!latin1.Contains("%%EOF", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("ملف PDF غير مكتمل أو تالف.");
        }

        if (DangerousPdfActionRegex().IsMatch(latin1))
        {
            throw new InvalidOperationException(
                "تم رفض ملف PDF لاحتوائه على محتوى نشط أو أوامر تنفيذية غير مسموحة (مثل JavaScript أو Launch أو ملفات مضمّنة).");
        }

        return data;
    }

    [GeneratedRegex(@"/(?:JavaScript|JS|Launch|OpenAction|AA|EmbeddedFile|RichMedia|XFA|SubmitForm|ImportData|GoToE|GoToR)\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 1000)]
    private static partial Regex DangerousPdfActionRegex();
}

/// <summary>
/// Built-in signature & polyglot scanner for uploaded evidence files.
/// Detects EICAR antivirus test string, embedded HTML/JS/PHP polyglots, and executable headers.
/// Can be replaced or composed with a ClamAV (clamd) scanner in production.
/// </summary>
public sealed class HeuristicEvidenceMalwareScanner : IEvidenceMalwareScanner
{
    private static readonly byte[] EicarSignature =
        Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    private static readonly byte[][] ForbiddenPatterns =
    [
        Encoding.ASCII.GetBytes("<script"),
        Encoding.ASCII.GetBytes("</script>"),
        Encoding.ASCII.GetBytes("<?php"),
        Encoding.ASCII.GetBytes("javascript:"),
        Encoding.ASCII.GetBytes("powershell -e")
    ];

    public Task<EvidenceScanResult> ScanAsync(
        ReadOnlyMemory<byte> fileBytes,
        string extension,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var span = fileBytes.Span;

        if (span.IndexOf(EicarSignature) >= 0)
        {
            return Task.FromResult(EvidenceScanResult.Malicious(
                "EICAR-Test-Signature",
                "تم رفض الملف لاكتشاف توقيع برمجي مشبوه."));
        }

        // Reject Windows PE ("MZ") or Linux ELF executables disguised with an allowed extension.
        if ((span.Length >= 2 && span[0] == 0x4D && span[1] == 0x5A) ||
            (span.Length >= 4 && span[0] == 0x7F && span[1] == 0x45 && span[2] == 0x4C && span[3] == 0x46))
        {
            return Task.FromResult(EvidenceScanResult.Malicious(
                "Executable-Header",
                "الملف المرفوع يبدو كملف تنفيذي غير مسموح."));
        }

        // Case-insensitive ASCII scan for web script polyglots embedded inside images/PDFs.
        var lowerAscii = Encoding.Latin1.GetString(span).ToLowerInvariant();
        foreach (var pattern in ForbiddenPatterns)
        {
            var token = Encoding.ASCII.GetString(pattern);
            if (lowerAscii.Contains(token, StringComparison.Ordinal))
            {
                return Task.FromResult(EvidenceScanResult.Malicious(
                    $"Embedded-Script:{token}",
                    "تم رفض الملف لاحتوائه على مقاطع برمجية أو سكربتات مضمّنة."));
            }
        }

        return Task.FromResult(EvidenceScanResult.Clean());
    }
}
