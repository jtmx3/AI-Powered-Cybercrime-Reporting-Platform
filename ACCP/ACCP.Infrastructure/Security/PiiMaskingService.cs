using System.Text.RegularExpressions;
using ACCP.Application.Security;

namespace ACCP.Infrastructure.Security;

/// <summary>
/// Redacts high-risk PII and credentials (emails, phone numbers, national IDs,
/// payment card numbers, IBANs, bearer/API tokens, and OTPs) before logging or AI processing.
/// </summary>
public sealed partial class PiiMaskingService : IPiiMaskingService
{
    public string MaskSensitiveText(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        var text = input;

        // 1. Bearer tokens / Brevo / OpenAI / generic API keys.
        text = SecretTokenRegex().Replace(text, "[REDACTED_TOKEN]");

        // 2. Payment card numbers (13-19 digits, optional spaces/hyphens, Luhn verified).
        text = CardCandidateRegex().Replace(text, match =>
        {
            var digits = new string(match.Value.Where(char.IsDigit).ToArray());
            return digits.Length is >= 13 and <= 19 && PassesLuhn(digits)
                ? "[REDACTED_CARD]"
                : match.Value;
        });

        // 3. IBAN numbers (including Jordan JOxx...).
        text = IbanRegex().Replace(text, "[REDACTED_IBAN]");

        // 4. Email addresses.
        text = EmailRegex().Replace(text, match => MaskEmail(match.Value) ?? "[REDACTED_EMAIL]");

        // 5. Jordanian & international phone numbers (preserving GUIDs and case numbers).
        text = PhoneRegex().Replace(text, "[REDACTED_PHONE]");

        // 6. Explicit password / OTP / PIN disclosures in text.
        text = SecretFieldRegex().Replace(text, "$1: [REDACTED_SECRET]");

        // 7. 10-digit national IDs when not part of a case number or GUID.
        text = NationalIdRegex().Replace(text, "[REDACTED_ID]");

        return text;
    }

    public string? MaskEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return null;
        }

        var trimmed = email.Trim();
        var atIndex = trimmed.IndexOf('@');
        if (atIndex <= 0 || atIndex >= trimmed.Length - 1)
        {
            return "[REDACTED_EMAIL]";
        }

        var local = trimmed[..atIndex];
        var domain = trimmed[(atIndex + 1)..];
        var visible = local.Length <= 2 ? local[..1] : local[..2];
        return $"{visible}***@{domain}";
    }

    private static bool PassesLuhn(string digits)
    {
        var sum = 0;
        var alternate = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var n = digits[i] - '0';
            if (alternate)
            {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }

    [GeneratedRegex(@"(?i)\b(?:bearer\s+[A-Za-z0-9\-._~+/]+=*|xkeysib-[A-Za-z0-9\-]+|xsmtpsib-[A-Za-z0-9\-]+|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,})\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex SecretTokenRegex();

    [GeneratedRegex(@"(?<!\w)(?:\d[ -]?){13,19}(?!\w)", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex CardCandidateRegex();

    [GeneratedRegex(@"(?i)\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex IbanRegex();

    [GeneratedRegex(@"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex EmailRegex();

    [GeneratedRegex(@"(?<!\w)(?:\+962|00962|0)7[789]\d{7}(?!\w)|(?<!\w)\+\d{1,3}[\s\-]?\d{7,12}(?!\w)", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex PhoneRegex();

    [GeneratedRegex(@"(?i)\b(password|passwd|otp|pin|كلمة\s*المرور|الرقم\s*السري|رمز\s*التحقق)\s*[:=]\s*\S+", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex SecretFieldRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9\-])\d{10}(?![A-Za-z0-9\-])", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex NationalIdRegex();
}
