namespace ACCP.Application.Security;

/// <summary>
/// Masks sensitive Personally Identifiable Information (PII) and credentials
/// before writing to audit logs, telemetry, or forwarding text to AI models.
/// </summary>
public interface IPiiMaskingService
{
    /// <summary>
    /// Redacts high-risk PII patterns (emails, phone numbers, national IDs,
    /// payment card numbers, IBANs, bearer tokens, and OTP/password leaks) from free text.
    /// </summary>
    string MaskSensitiveText(string? input);

    /// <summary>
    /// Masks an email address while preserving minimal domain context (e.g. a***@example.com).
    /// </summary>
    string? MaskEmail(string? email);
}
