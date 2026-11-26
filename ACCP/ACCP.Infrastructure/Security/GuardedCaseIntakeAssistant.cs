using ACCP.Application.Chat;
using Microsoft.Extensions.Logging;

namespace ACCP.Infrastructure.Security;

/// <summary>
/// Security decorator wrapping any ICaseIntakeAssistant implementation.
/// Enforces AI guardrails (prompt injection blocking, PII masking, isolated stateless context,
/// and output policy checks) before and after invoking the underlying AI model.
/// </summary>
public sealed class GuardedCaseIntakeAssistant : ICaseIntakeAssistant
{
    private readonly ICaseIntakeAssistant _inner;
    private readonly IIntakePromptGuard _guard;
    private readonly ILogger<GuardedCaseIntakeAssistant> _logger;

    public GuardedCaseIntakeAssistant(
        ICaseIntakeAssistant inner,
        IIntakePromptGuard guard,
        ILogger<GuardedCaseIntakeAssistant> logger)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _guard = guard ?? throw new ArgumentNullException(nameof(guard));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<IntakeAssistantReply> ReplyAsync(
        IReadOnlyList<IntakeChatMessage> conversation,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(conversation);

        // 1. Inspect every user message and build a fresh, PII-masked, isolated session snapshot.
        IReadOnlyList<IntakeChatMessage> isolatedConversation;
        try
        {
            isolatedConversation = _guard.PrepareIsolatedConversation(conversation);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(
                "AI Guardrail blocked intake input under policy {PolicyVersion}.",
                IntakeSystemPromptPolicy.PolicyVersion);
            throw new InvalidOperationException(ex.Message);
        }

        // 2. Call underlying AI provider with isolated, stateless conversation context.
        var reply = await _inner.ReplyAsync(isolatedConversation, cancellationToken);

        // 3. Inspect assistant output for prompt leakage or unauthorized legal advice.
        var outputCheck = _guard.InspectAssistantReply(reply);
        if (!outputCheck.IsAllowed)
        {
            _logger.LogWarning(
                "AI Guardrail blocked assistant output. Rule: {Rule}, Policy: {PolicyVersion}.",
                outputCheck.MatchedRule,
                IntakeSystemPromptPolicy.PolicyVersion);

            throw new InvalidOperationException(
                outputCheck.UserFacingMessage ?? "تم إيقاف رد المساعد لمخالفته سياسات الأمان.");
        }

        return reply;
    }
}
