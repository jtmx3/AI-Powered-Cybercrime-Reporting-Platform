using ACCP.Application.Chat;

namespace ACCP.Web.Services.Chat;

public sealed class UnavailableCaseIntakeAssistant : ICaseIntakeAssistant
{
    public Task<IntakeAssistantReply> ReplyAsync(
        IReadOnlyList<IntakeChatMessage> conversation,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(conversation);

        return Task.FromException<IntakeAssistantReply>(
            new InvalidOperationException(
                "خدمة المساعد والتقييم غير متاحة حاليًا. لم يتم إنشاء تقييم أو إرسال بلاغ. حاول لاحقًا."));
    }
}
