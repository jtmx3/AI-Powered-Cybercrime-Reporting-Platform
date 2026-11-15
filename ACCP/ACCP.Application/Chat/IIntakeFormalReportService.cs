using System;
using System.Threading;
using System.Threading.Tasks;

namespace ACCP.Application.Chat;

public interface IIntakeFormalReportService
{
    Task<IntakeFormalReportInfo> SubmitAsync(
        Guid conversationId,
        Guid assessmentId,
        bool consent,
        CancellationToken cancellationToken = default);
}

public sealed record IntakeFormalReportInfo(
    Guid ConversationId,
    Guid CaseId,
    string CaseNumber,
    Guid AssessmentId,
    DateTime ConsentAtUtc,
    bool AlreadySubmitted);