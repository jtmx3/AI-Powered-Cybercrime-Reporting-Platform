using System;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ACCP.Application.Chat;
using ACCP.Application.Security;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Web.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ACCP.Web.Services.Chat;

public sealed class StaffIntakeHistoryService : IStaffIntakeHistoryService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly CaseAuthorizationService _authorization;

    public StaffIntakeHistoryService(
        IServiceScopeFactory scopes,
        CaseAuthorizationService authorization)
    {
        _scopes = scopes;
        _authorization = authorization;
    }

    public async Task<StaffIntakeHistory?> GetForCaseAsync(
        Guid caseId,
        CancellationToken cancellationToken = default)
    {
        if (caseId == Guid.Empty)
        {
            throw new ArgumentException(
                "معرّف القضية غير صالح.");
        }

        await using var scope = _scopes.CreateAsyncScope();

        var db = scope.ServiceProvider
            .GetRequiredService<AccpDbContext>();

        return await db.Database
            .CreateExecutionStrategy()
            .ExecuteAsync(async () =>
            {
                await using var transaction =
                    await db.Database.BeginTransactionAsync(
                        IsolationLevel.Serializable,
                        cancellationToken);

                var actor =
                    await _authorization.GetCurrentActorAsync(
                        cancellationToken);

                if (actor is null || !actor.HasRole("OFFICER"))
                    throw NoAccess();

                var account = await db.Users
                    .AsNoTracking()
                    .SingleOrDefaultAsync(
                        x => x.Id == actor.UserId,
                        cancellationToken);

                var roles = await db.UserRoles
                    .Where(x => x.UserId == actor.UserId)
                    .Join(
                        db.Roles,
                        x => x.RoleId,
                        x => x.Id,
                        (_, role) => role.Name)
                    .ToListAsync(cancellationToken);

                if (account is null ||
                    !account.IsActive ||
                    !account.TwoFactorEnabled ||
                    !roles.Contains("OFFICER") ||
                    (account.LockoutEnabled &&
                     account.LockoutEnd > DateTimeOffset.UtcNow))
                {
                    throw NoAccess();
                }

                // التحقق من علاقة الموظف بالقضية قبل قراءة المحادثة.
                var cyberCase = await db.CyberCases
                    .AsNoTracking()
                    .Where(x => x.Id == caseId)
                    .Select(x => new CyberCase
                    {
                        Id = x.Id,
                        ReporterId = x.ReporterId,
                        Path = x.Path,
                        AssignedOfficerId = x.AssignedOfficerId,

                        Collaborators = x.Collaborators
                            .Where(c => c.IsActive)
                            .Select(c => new CaseCollaborator
                            {
                                CyberCaseId = c.CyberCaseId,
                                OfficerId = c.OfficerId,
                                IsActive = c.IsActive
                            })
                            .ToList()
                    })
                    .SingleOrDefaultAsync(cancellationToken);

                if (cyberCase is null ||
                    cyberCase.Path != CasePath.FormalReport ||
                    !CaseAccessPolicy.IsAllowed(
                        actor,
                        cyberCase,
                        CasePermission.ReadDetails))
                {
                    throw NoAccess();
                }

                var conversation = await db.IntakeConversations
                    .AsNoTracking()
                    .SingleOrDefaultAsync(
                        x => x.CyberCaseId == caseId,
                        cancellationToken);

                if (conversation is null)
                {
                    // البلاغات القديمة قد لا ترتبط بمحادثة استقبال.
                    await transaction.CommitAsync(
                        cancellationToken);

                    return (StaffIntakeHistory?)null;
                }

                if (conversation.ReporterId != cyberCase.ReporterId ||
                    conversation.FormalReportConsentAtUtc
                        is not { } consentAt ||
                    conversation.FormalReportAssessmentId
                        is not { } assessmentId)
                {
                    throw InvalidHistory();
                }

                var stored = await db.IntakeRiskAssessments
                    .AsNoTracking()
                    .SingleOrDefaultAsync(
                        x => x.Id == assessmentId &&
                             x.ConversationId == conversation.Id,
                        cancellationToken);

                if (stored is null)
                    throw InvalidHistory();

                var assessment = new CaseRiskAssessment(
                    stored.Title,
                    stored.Summary,
                    stored.IncidentType,
                    stored.RiskPercentage,
                    stored.RiskExplanation);

                if (!assessment.ShouldOfferFormalReport)
                    throw InvalidHistory();

                var approvedMessage =
                    await db.IntakeConversationMessages
                        .AsNoTracking()
                        .SingleOrDefaultAsync(
                            x => x.ConversationId == conversation.Id &&
                                 x.Id == stored.AssistantMessageId,
                            cancellationToken);

                if (approvedMessage is null ||
                    approvedMessage.Role != IntakeMessageRole.Assistant ||
                    approvedMessage.AuthorUserId is not null ||
                    approvedMessage.SequenceNumber <=
                        stored.BasedOnSequenceNumber)
                {
                    throw InvalidHistory();
                }

                // عرض السجل حتى رد المساعد المعتمد لتقديم البلاغ.
                var messages =
                    await db.IntakeConversationMessages
                        .AsNoTracking()
                        .Where(x =>
                            x.ConversationId == conversation.Id &&
                            x.SequenceNumber <=
                                approvedMessage.SequenceNumber)
                        .OrderBy(x => x.SequenceNumber)
                        .Take(401)
                        .ToListAsync(cancellationToken);

                if (messages.Count == 0 ||
                    messages.Count > 400 ||
                    messages.Any(x =>
                        x.SequenceNumber <= 0 ||
                        x.Role is not (
                            IntakeMessageRole.Reporter or
                            IntakeMessageRole.Assistant) ||
                        (x.Role == IntakeMessageRole.Reporter &&
                         x.AuthorUserId != conversation.ReporterId) ||
                        (x.Role == IntakeMessageRole.Assistant &&
                         x.AuthorUserId is not null)))
                {
                    throw InvalidHistory();
                }

                var basis = messages.SingleOrDefault(
                    x => x.SequenceNumber ==
                         stored.BasedOnSequenceNumber);

                if (basis is null ||
                    basis.Role != IntakeMessageRole.Reporter ||
                    basis.OperationId == Guid.Empty ||
                    basis.OperationId != approvedMessage.OperationId ||
                    messages[^1].Id != approvedMessage.Id)
                {
                    throw InvalidHistory();
                }

                var confirmed =
                    await _authorization.GetCurrentActorAsync(
                        cancellationToken);

                if (confirmed?.UserId != actor.UserId ||
                    !confirmed.HasRole("OFFICER"))
                {
                    throw NoAccess();
                }

                var result = new StaffIntakeHistory(
                    conversation.Id,
                    consentAt,
                    assessment,
                    messages.Select(x => new StaffIntakeMessage(
                        x.SequenceNumber,
                        x.Role == IntakeMessageRole.Reporter
                            ? IntakeChatRole.User
                            : IntakeChatRole.Assistant,
                        x.Content,
                        x.CreatedAtUtc))
                    .ToArray());

                await transaction.CommitAsync(
                    cancellationToken);

                return result;
            });
    }

    private static UnauthorizedAccessException NoAccess() =>
        new("لا تملك صلاحية عرض سجل استقبال هذه القضية.");

    private static InvalidOperationException InvalidHistory() =>
        new("تعذر التحقق من سجل الاستقبال والتقييم المعتمد.");
}