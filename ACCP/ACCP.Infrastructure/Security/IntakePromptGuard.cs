using System.Text;
using System.Text.RegularExpressions;
using ACCP.Application.Chat;
using ACCP.Application.Security;

namespace ACCP.Infrastructure.Security;

/// <summary>
/// AI Guardrails for the cybercrime intake assistant:
/// - Blocks Arabic & English prompt injection, jailbreaks, role spoofing, and risk-score manipulation.
/// - Strips zero-width / bidirectional spoofing characters.
/// - Masks high-risk PII before forwarding conversation turns to any LLM.
/// - Enforces strict per-session context isolation (bounded sliding window, no cross-session state).
/// - Validates assistant output to block system-prompt leakage and unauthorized legal advice.
/// </summary>
public sealed partial class IntakePromptGuard : IIntakePromptGuard
{
    private const int MaxIsolatedTurns = 24;
    private readonly IPiiMaskingService _piiMasking;

    public IntakePromptGuard(IPiiMaskingService piiMasking)
    {
        _piiMasking = piiMasking ?? throw new ArgumentNullException(nameof(piiMasking));
    }

    public PromptGuardInspectionResult InspectUserInput(string? content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return PromptGuardInspectionResult.Allowed();
        }

        var normalized = RemoveObfuscationChars(content);

        if (EnglishInjectionRegex().IsMatch(normalized))
        {
            return PromptGuardInspectionResult.Blocked(
                "PromptInjection.English",
                "تم حظر الرسالة لاحتوائها على محاولة توجيه غير مسموحة لنموذج المساعد. يرجى وصف وقائع الحادثة فقط.");
        }

        if (ArabicInjectionRegex().IsMatch(normalized))
        {
            return PromptGuardInspectionResult.Blocked(
                "PromptInjection.Arabic",
                "تم حظر الرسالة لاحتوائها على محاولة تجاوز تعليمات المساعد. يرجى وصف وقائع الحادثة فقط.");
        }

        if (RoleSpoofingRegex().IsMatch(normalized))
        {
            return PromptGuardInspectionResult.Blocked(
                "PromptInjection.RoleSpoofing",
                "تم حظر الرسالة لاحتوائها على وسوم أو تنسيقات نظام غير مسموحة.");
        }

        if (RiskManipulationRegex().IsMatch(normalized))
        {
            return PromptGuardInspectionResult.Blocked(
                "PromptInjection.RiskManipulation",
                "لا يمكن فرض أو تعديل نسبة الخطورة يدوياً عبر المحادثة. يرجى سرد التفاصيل الموضوعية للحادثة فقط.");
        }

        return PromptGuardInspectionResult.Allowed();
    }

    public IReadOnlyList<IntakeChatMessage> PrepareIsolatedConversation(
        IReadOnlyList<IntakeChatMessage> conversation)
    {
        ArgumentNullException.ThrowIfNull(conversation);

        // Enforce strict session isolation & bounded context window.
        var recent = conversation.Count > MaxIsolatedTurns
            ? conversation.Skip(conversation.Count - MaxIsolatedTurns)
            : conversation;

        var isolated = new List<IntakeChatMessage>(Math.Min(conversation.Count, MaxIsolatedTurns));

        foreach (var turn in recent)
        {
            var cleaned = RemoveObfuscationChars(turn.Content);

            if (turn.Role == IntakeChatRole.User)
            {
                var inspection = InspectUserInput(cleaned);
                if (!inspection.IsAllowed)
                {
                    throw new InvalidOperationException(
                        inspection.UserFacingMessage ?? "تم حظر محتوى غير مسموح في المحادثة.");
                }

                // Mask sensitive PII (national IDs, IBANs, credit cards, passwords, OTPs, phones)
                // before sending reporter text to the AI provider.
                var masked = _piiMasking.MaskSensitiveText(cleaned);
                isolated.Add(new IntakeChatMessage(
                    IntakeChatRole.User,
                    $"<untrusted_reporter_input>\n{masked}\n</untrusted_reporter_input>"));
            }
            else
            {
                isolated.Add(new IntakeChatMessage(IntakeChatRole.Assistant, cleaned));
            }
        }

        return isolated;
    }

    public PromptGuardInspectionResult InspectAssistantReply(IntakeAssistantReply reply)
    {
        ArgumentNullException.ThrowIfNull(reply);

        var message = reply.Message ?? string.Empty;

        // Block accidental system-prompt disclosure.
        if (message.Contains("wathiq-intake-policy", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("untrusted_reporter_input", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("القواعد الصارمة التالية غير قابلة للتغيير", StringComparison.Ordinal))
        {
            return PromptGuardInspectionResult.Blocked(
                "OutputGuard.PromptLeakage",
                "تم إيقاف رد المساعد لأسباب أمنية. يرجى إعادة المحاولة.");
        }

        // Block direct legal advice claims that violate IntakeSystemPromptPolicy.
        if (UnauthorizedLegalAdviceRegex().IsMatch(message))
        {
            return PromptGuardInspectionResult.Blocked(
                "OutputGuard.LegalAdviceViolation",
                "تم إيقاف رد المساعد لمخالفته سياسة منع تقديم الاستشارات القانونية.");
        }

        return PromptGuardInspectionResult.Allowed();
    }

    private static string RemoveObfuscationChars(string input)
    {
        var sb = new StringBuilder(input.Length);
        foreach (var ch in input)
        {
            if (ch is (>= '\u200B' and <= '\u200F')
                or (>= '\u202A' and <= '\u202E')
                or (>= '\u2060' and <= '\u2069')
                or '\uFEFF')
            {
                continue;
            }

            sb.Append(ch);
        }

        return sb.ToString();
    }

    [GeneratedRegex(@"(?i)\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions?|prompts?|rules?|policies?)|reveal\s+(?:your\s+)?(?:system\s+prompt|hidden\s+instructions?)|jailbreak|\bDAN\s+mode\b|developer\s+mode\s+enabled", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex EnglishInjectionRegex();

    [GeneratedRegex(@"(?:تجاهل|انسَ|انس|الغي|ألغِ|تجاوز)\s+(?:كل\s+|جميع\s+)?(?:التعليمات|الأوامر|القواعد|القيود)\s*(?:السابقة|النظامية|الأصلية)?|اكشف\s+(?:عن\s+)?(?:تعليمات\s+النظام|البرومبت)|أنت\s+الآن\s+(?:محام|قاض|ضابط|في\s+وضع\s+المطور)", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex ArabicInjectionRegex();

    [GeneratedRegex(@"(?i)(?:<\|(?:system|im_start|im_end|assistant)\|>\s*|^\s*###\s*(?:system|instruction)\s*:|\[\s*SYSTEM\s*\])", RegexOptions.Compiled | RegexOptions.Multiline, matchTimeoutMilliseconds: 500)]
    private static partial Regex RoleSpoofingRegex();

    [GeneratedRegex(@"(?i)(?:set|force|output|make|return)\s+(?:the\s+)?risk(?:_?percentage|_?score)?\s*(?:to|=|:)?\s*\d{1,3}\s*%?|(?:اجعل|اضبط|ضع|حدّد|حدد|ارفع|اخفض)\s+(?:نسبة|درجة)\s+الخطورة\s*(?:إلى|الى|=|:)?\s*\d{1,3}", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex RiskManipulationRegex();

    [GeneratedRegex(@"(?i)(?:بصفتي\s+محاميك|أقدم\s+لك\s+استشارة\s+قانونية\s+ملزمة|أضمن\s+لك\s+الحكم\s+القضائي|as\s+your\s+lawyer\s+i\s+advise)", RegexOptions.Compiled, matchTimeoutMilliseconds: 500)]
    private static partial Regex UnauthorizedLegalAdviceRegex();
}
