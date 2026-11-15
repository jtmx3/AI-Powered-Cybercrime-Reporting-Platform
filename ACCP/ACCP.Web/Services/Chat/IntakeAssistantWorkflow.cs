using System.Data;
using ACCP.Application.Chat;
using ACCP.Domain.Entities;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using ACCP.Web.Security;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ACCP.Web.Services.Chat;

public sealed class IntakeAssistantWorkflow : IIntakeAssistantWorkflow
{
    private readonly IServiceScopeFactory _scopes;
    private readonly CaseAuthorizationService _authorization;
    private readonly ICaseIntakeAssistant _assistant;

    public IntakeAssistantWorkflow(
        IServiceScopeFactory scopes,
        CaseAuthorizationService authorization,
        ICaseIntakeAssistant assistant)
    {
        _scopes = scopes;
        _authorization = authorization;
        _assistant = assistant;
    }

    public async Task<IntakeAssistantTurn> ReplyAsync(
        Guid conversationId,
        Guid operationId,
        CancellationToken cancellationToken = default)
    {
        RequireId(operationId);

        var snapshot = await ExecuteAsync(
            conversationId,
            async (db, conversation, reporterId, ct) =>
            {
                var messages = await db.IntakeConversationMessages
                    .AsNoTracking()
                    .Where(x => x.ConversationId == conversationId)
                    .OrderBy(x => x.SequenceNumber)
                    .Take(401)
                    .ToListAsync(ct);

                var reporterMessage = messages.SingleOrDefault(x =>
                    x.OperationId == operationId &&
                    x.Role == IntakeMessageRole.Reporter &&
                    x.AuthorUserId == reporterId);

                if (reporterMessage is null)
                    throw new InvalidOperationException(
                        "احفظ رسالتك قبل طلب رد المساعد.");

                var cached = await FindReplyAsync(
                    db, reporterMessage, ct);

                if (cached is not null)
                    return new ReplySnapshot(
                        reporterId, 0, [], [], cached);

                RequireOpen(conversation);
                RequireLatestReporter(messages, reporterMessage);

                if (messages.Count >= 400)
                    throw new InvalidOperationException(
                        "وصلت المحادثة للحد المتاح من الرسائل.");

                if (messages.Any(x => x.Role is not (
                    IntakeMessageRole.Reporter or
                    IntakeMessageRole.Assistant)))
                    throw new InvalidOperationException(
                        "هذه المحادثة غير متاحة للمساعد الآلي.");

                var history = messages.Select(x =>
                    new IntakeChatMessage(
                        x.Role == IntakeMessageRole.Reporter
                            ? IntakeChatRole.User
                            : IntakeChatRole.Assistant,
                        x.Content))
                    .ToArray();

                return new ReplySnapshot(
                    reporterId,
                    reporterMessage.SequenceNumber,
                    conversation.RowVersion.ToArray(),
                    history,
                    null);
            },
            cancellationToken);

        if (snapshot.Cached is not null)
            return snapshot.Cached;

        // استدعاء المساعد خارج معاملة قاعدة البيانات.
        var reply = await _assistant.ReplyAsync(
            snapshot.History,
            cancellationToken);

        cancellationToken.ThrowIfCancellationRequested();

        if (reply is null)
            throw new InvalidOperationException(
                "لم يُرجع المساعد ردًا صالحًا.");

        var content = ValidateContent(reply.Message);

        return await ExecuteAsync(
            conversationId,
            async (db, conversation, reporterId, ct) =>
            {
                if (reporterId != snapshot.ReporterId)
                    throw NoAccess();

                var reporterMessage = await db.IntakeConversationMessages
                    .SingleOrDefaultAsync(x =>
                        x.ConversationId == conversationId &&
                        x.OperationId == operationId &&
                        x.Role == IntakeMessageRole.Reporter &&
                        x.AuthorUserId == reporterId, ct);

                if (reporterMessage is null)
                    throw NoAccess();

                var cached = await FindReplyAsync(
                    db, reporterMessage, ct);

                if (cached is not null)
                    return cached;

                RequireOpen(conversation);

                var lastSequence = await db.IntakeConversationMessages
                    .Where(x => x.ConversationId == conversationId)
                    .Select(x => (long?)x.SequenceNumber)
                    .MaxAsync(ct) ?? 0;

                if (lastSequence != snapshot.BasedOnSequenceNumber ||
                    reporterMessage.SequenceNumber !=
                        snapshot.BasedOnSequenceNumber ||
                    !conversation.RowVersion.SequenceEqual(
                        snapshot.RowVersion))
                    throw new InvalidOperationException(
                        "تغيرت المحادثة أثناء توليد الرد. " +
                        "حدّث المحادثة ثم أعد المحاولة.");

                if (await db.IntakeConversationMessages.CountAsync(
                    x => x.ConversationId == conversationId, ct) >= 400)
                    throw new InvalidOperationException(
                        "وصلت المحادثة للحد المتاح من الرسائل.");

                var now = DateTime.UtcNow;

                var message = new IntakeConversationMessage
                {
                    ConversationId = conversationId,
                    OperationId = operationId,
                    SequenceNumber = checked(lastSequence + 1),
                    Role = IntakeMessageRole.Assistant,
                    AuthorUserId = null,
                    Content = content,
                    CreatedAtUtc = now
                };

                db.IntakeConversationMessages.Add(message);

                IntakeRiskAssessment? assessment = null;

                if (reply.Assessment is { } result)
                {
                    assessment = new IntakeRiskAssessment(
                        conversationId,
                        message.Id,
                        reporterMessage.SequenceNumber,
                        result.Title,
                        result.Summary,
                        result.IncidentType,
                        decimal.Round(
                            result.RiskPercentage,
                            26,
                            MidpointRounding.ToEven),
                        result.RiskExplanation);

                    db.IntakeRiskAssessments.Add(assessment);

                    conversation.Title = assessment.Title;
                }

                conversation.UpdatedAtUtc = now;

                conversation.Status =
                    assessment?.ShouldOfferFormalReport == true
                        ? IntakeConversationStatus.AwaitingReportDecision
                        : IntakeConversationStatus.Assistant;

                // حفظ الرد والتقييم وحالة المحادثة معًا.
                await db.SaveChangesAsync(ct);

                return new IntakeAssistantTurn(
                    ToMessage(message),
                    assessment is null
                        ? null
                        : ToAssessment(assessment));
            },
            cancellationToken);
    }

    public Task<IntakeAssessmentInfo?> GetCurrentAssessmentAsync(
        Guid conversationId,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync<IntakeAssessmentInfo?>(
            conversationId,
            async (db, conversation, _, ct) =>
            {
                if (!IsOpen(conversation))
                    return null;

                var last = await db.IntakeConversationMessages
                    .AsNoTracking()
                    .Where(x => x.ConversationId == conversationId)
                    .OrderByDescending(x => x.SequenceNumber)
                    .FirstOrDefaultAsync(ct);

                if (last?.Role != IntakeMessageRole.Assistant)
                    return null;

                var reporterSequence = await db.IntakeConversationMessages
                    .Where(x =>
                        x.ConversationId == conversationId &&
                        x.Role == IntakeMessageRole.Reporter)
                    .Select(x => (long?)x.SequenceNumber)
                    .MaxAsync(ct);

                var assessment = await db.IntakeRiskAssessments
                    .AsNoTracking()
                    .SingleOrDefaultAsync(x =>
                        x.ConversationId == conversationId &&
                        x.AssistantMessageId == last.Id &&
                        x.BasedOnSequenceNumber == reporterSequence, ct);

                return assessment is null
                    ? null
                    : ToAssessment(assessment);
            },
            cancellationToken);

    private static async Task<IntakeAssistantTurn?> FindReplyAsync(
        AccpDbContext db,
        IntakeConversationMessage reporterMessage,
        CancellationToken ct)
    {
        var message = await db.IntakeConversationMessages
            .AsNoTracking()
            .SingleOrDefaultAsync(x =>
                x.ConversationId == reporterMessage.ConversationId &&
                x.OperationId == reporterMessage.OperationId &&
                x.Role == IntakeMessageRole.Assistant, ct);

        if (message is null)
            return null;

        if (message.SequenceNumber <= reporterMessage.SequenceNumber)
            throw new InvalidOperationException(
                "ترتيب رسائل المحادثة غير صالح.");

        var assessment = await db.IntakeRiskAssessments
            .AsNoTracking()
            .SingleOrDefaultAsync(x =>
                x.ConversationId == message.ConversationId &&
                x.AssistantMessageId == message.Id, ct);

        if (assessment is not null &&
            assessment.BasedOnSequenceNumber !=
                reporterMessage.SequenceNumber)
            throw new InvalidOperationException(
                "التقييم غير مرتبط بالرسالة المطلوبة.");

        return new IntakeAssistantTurn(
            ToMessage(message),
            assessment is null
                ? null
                : ToAssessment(assessment));
    }

    private async Task<T> ExecuteAsync<T>(
        Guid conversationId,
        Func<
            AccpDbContext,
            IntakeConversation,
            Guid,
            CancellationToken,
            Task<T>> action,
        CancellationToken ct)
    {
        RequireId(conversationId);

        for (var attempt = 0; ; attempt++)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
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
                                ct);

                        db.ChangeTracker.Clear();

                        var reporterId = await RequireReporterAsync(
                            db, ct);

                        var conversation = await db.IntakeConversations
                            .SingleOrDefaultAsync(x =>
                                x.Id == conversationId &&
                                x.ReporterId == reporterId, ct);

                        if (conversation is null)
                            throw NoAccess();

                        var result = await action(
                            db,
                            conversation,
                            reporterId,
                            ct);

                        await transaction.CommitAsync(ct);

                        return result;
                    });
            }
            catch (Exception exception) when (
                attempt < 2 && IsRetryableConflict(exception))
            {
                await Task.Delay(
                    TimeSpan.FromMilliseconds(40 * (attempt + 1)),
                    ct);
            }
        }
    }

    private async Task<Guid> RequireReporterAsync(
        AccpDbContext db,
        CancellationToken ct)
    {
        var actor = await _authorization.GetCurrentActorAsync(ct);

        if (actor is null || !actor.HasRole(IdentityRoles.User))
            throw NoAccess();

        var account = await db.Users
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.Id == actor.UserId, ct);

        var roles = await db.UserRoles
            .Where(x => x.UserId == actor.UserId)
            .Join(
                db.Roles,
                x => x.RoleId,
                x => x.Id,
                (_, role) => role.Name)
            .ToListAsync(ct);

        if (account is null ||
            !account.IsActive ||
            (account.LockoutEnabled &&
             account.LockoutEnd > DateTimeOffset.UtcNow) ||
            roles.Count != 1 ||
            roles[0] != IdentityRoles.User)
            throw NoAccess();

        var confirmed = await _authorization.GetCurrentActorAsync(ct);

        if (confirmed?.UserId != actor.UserId ||
            !confirmed.HasRole(IdentityRoles.User))
            throw NoAccess();

        return actor.UserId;
    }

    private static void RequireLatestReporter(
        IReadOnlyList<IntakeConversationMessage> messages,
        IntakeConversationMessage reporterMessage)
    {
        if (messages.Count == 0 ||
            messages[^1].Id != reporterMessage.Id)
            throw new InvalidOperationException(
                "يمكن توليد رد جديد لآخر رسالة فقط. " +
                "حدّث المحادثة ثم أعد المحاولة.");
    }

    private static bool IsOpen(IntakeConversation conversation) =>
        conversation.CyberCaseId is null &&
        conversation.FormalReportConsentAtUtc is null &&
        conversation.Status is (
            IntakeConversationStatus.Assistant or
            IntakeConversationStatus.AwaitingReportDecision);

    private static void RequireOpen(
        IntakeConversation conversation)
    {
        if (!IsOpen(conversation))
            throw new InvalidOperationException(
                "هذه المحادثة غير متاحة للمساعد الآلي.");
    }

    private static string ValidateContent(string? value)
    {
        var text = value?.Trim() ?? string.Empty;

        if (text.Length is < 1 or > 6000 ||
            text.Any(c =>
                char.IsControl(c) &&
                c is not ('\r' or '\n' or '\t')))
            throw new InvalidOperationException(
                "لم يُرجع المساعد ردًا صالحًا للحفظ.");

        return text;
    }

    private static bool IsRetryableConflict(Exception exception) =>
        exception is DbUpdateConcurrencyException ||
        exception is SqlException
        {
            Number: 1205 or 2601 or 2627
        } ||
        exception is DbUpdateException
        {
            InnerException: SqlException
            {
                Number: 1205 or 2601 or 2627
            }
        };

    private static void RequireId(Guid id)
    {
        if (id == Guid.Empty)
            throw new ArgumentException(
                "معرّف الطلب غير صالح.");
    }

    private static UnauthorizedAccessException NoAccess() =>
        new("تعذر الوصول إلى المحادثة.");

    private static IntakeMessageInfo ToMessage(
        IntakeConversationMessage item) =>
        new(
            item.Id,
            item.SequenceNumber,
            item.Role,
            item.Content,
            item.OperationId,
            item.CreatedAtUtc);

    private static IntakeAssessmentInfo ToAssessment(
        IntakeRiskAssessment item) =>
        new(
            item.Id,
            item.AssistantMessageId,
            item.BasedOnSequenceNumber,
            new CaseRiskAssessment(
                item.Title,
                item.Summary,
                item.IncidentType,
                item.RiskPercentage,
                item.RiskExplanation),
            item.CreatedAtUtc);

    private sealed record ReplySnapshot(
        Guid ReporterId,
        long BasedOnSequenceNumber,
        byte[] RowVersion,
        IReadOnlyList<IntakeChatMessage> History,
        IntakeAssistantTurn? Cached);
}