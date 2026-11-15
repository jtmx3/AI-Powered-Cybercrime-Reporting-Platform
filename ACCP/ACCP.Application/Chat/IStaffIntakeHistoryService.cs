using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace ACCP.Application.Chat;

public interface IStaffIntakeHistoryService
{
    Task<StaffIntakeHistory?> GetForCaseAsync(
        Guid caseId,
        CancellationToken cancellationToken = default);
}

public sealed record StaffIntakeHistory(
    Guid ConversationId,
    DateTime ConsentAtUtc,
    CaseRiskAssessment Assessment,
    IReadOnlyList<StaffIntakeMessage> Messages);

public sealed record StaffIntakeMessage(
    long SequenceNumber,
    IntakeChatRole Role,
    string Content,
    DateTime CreatedAtUtc);