using System.Data;
using ACCP.Application.Chat;
using ACCP.Domain.Entities;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using ACCP.Web.Security;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace ACCP.Web.Services.Chat;

public sealed class IntakeConversationService : IIntakeConversationService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly CaseAuthorizationService _authorization;

    public IntakeConversationService(
        IServiceScopeFactory scopes,
        CaseAuthorizationService authorization)
    {
        _scopes = scopes;
        _authorization = authorization;
    }

    public Task<IntakeConversationInfo> CreateAsync(
        Guid conversationId,
        CancellationToken cancellationToken = default)
    {
        RequireId(conversationId);

        return WriteAsync(async (db, reporterId, ct) =>
        {
            var existing = await db.IntakeConversations
                .SingleOrDefaultAsync(x => x.Id == conversationId, ct);

            if (existing is not null)
            {
                if (existing.ReporterId != reporterId) throw NoAccess();
                return ToInfo(existing);
            }

            var now = DateTime.UtcNow;
            var conversation = new IntakeConversation
            {
                Id = conversationId,
                ReporterId = reporterId,
                Title = "محادثة جديدة",
                Status = IntakeConversationStatus.Assistant,
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };

            db.IntakeConversations.Add(conversation);
            await db.SaveChangesAsync(ct);
            return ToInfo(conversation);
        }, cancellationToken);
    }

    public async Task<IntakeConversationInfo?> GetAsync(
        Guid conversationId,
        CancellationToken cancellationToken = default)
    {
        RequireId(conversationId);
        await using var scope = _scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var reporterId = await RequireReporterAsync(db, cancellationToken);

        var item = await db.IntakeConversations.AsNoTracking()
            .SingleOrDefaultAsync(
                x => x.Id == conversationId && x.ReporterId == reporterId,
                cancellationToken);

        return item is null ? null : ToInfo(item);
    }

    public async Task<IReadOnlyList<IntakeConversationInfo>> ListAsync(
        int skip = 0,
        int take = 20,
        CancellationToken cancellationToken = default)
    {
        if (skip < 0 || take is < 1 or > 100)
            throw new ArgumentOutOfRangeException(nameof(take));

        await using var scope = _scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var reporterId = await RequireReporterAsync(db, cancellationToken);

        var items = await db.IntakeConversations.AsNoTracking()
            .Where(x => x.ReporterId == reporterId)
            .OrderByDescending(x => x.UpdatedAtUtc)
            .ThenBy(x => x.Id)
            .Skip(skip)
            .Take(take)
            .ToListAsync(cancellationToken);

        return items.Select(ToInfo).ToArray();
    }

    public async Task<IntakeMessagePage> GetMessagesAsync(
        Guid conversationId,
        long afterSequenceNumber = 0,
        int take = 50,
        CancellationToken cancellationToken = default)
    {
        RequireId(conversationId);

        if (afterSequenceNumber < 0 || take is < 1 or > 100)
            throw new ArgumentOutOfRangeException(nameof(take));

        await using var scope = _scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var reporterId = await RequireReporterAsync(db, cancellationToken);

        if (!await db.IntakeConversations.AnyAsync(
            x => x.Id == conversationId && x.ReporterId == reporterId,
            cancellationToken))
            throw NoAccess();

        var items = await db.IntakeConversationMessages.AsNoTracking()
            .Where(x =>
                x.ConversationId == conversationId &&
                x.Conversation.ReporterId == reporterId &&
                x.SequenceNumber > afterSequenceNumber)
            .OrderBy(x => x.SequenceNumber)
            .Take(take + 1)
            .ToListAsync(cancellationToken);

        var hasMore = items.Count > take;
        var page = items.Take(take).Select(ToMessage).ToArray();

        return new IntakeMessagePage(
            page,
            hasMore,
            page.Length == 0
                ? afterSequenceNumber
                : page[^1].SequenceNumber);
    }

    public Task<IntakeMessageInfo> AppendReporterMessageAsync(
        Guid conversationId,
        Guid operationId,
        string content,
        CancellationToken cancellationToken = default)
    {
        RequireId(conversationId);
        RequireId(operationId);

        var text = content?.Trim() ?? string.Empty;

        if (text.Length is < 2 or > 3000 ||
            text.Any(c => char.IsControl(c) &&
                c is not ('\r' or '\n' or '\t')))
            throw new ArgumentException(
                "اكتب رسالة بين حرفين و3000 حرف بدون محارف تحكم غير صالحة.",
                nameof(content));

        return WriteAsync(async (db, reporterId, ct) =>
        {
            var conversation = await db.IntakeConversations
                .SingleOrDefaultAsync(
                    x => x.Id == conversationId &&
                         x.ReporterId == reporterId, ct);

            if (conversation is null) throw NoAccess();

            var previous = await db.IntakeConversationMessages
                .SingleOrDefaultAsync(
                    x => x.ConversationId == conversationId &&
                         x.OperationId == operationId &&
                         x.Role == IntakeMessageRole.Reporter, ct);

            if (previous is not null)
            {
                if (previous.AuthorUserId != reporterId ||
                    !string.Equals(
                        previous.Content, text, StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        "لا يمكن استخدام معرّف الرسالة نفسه لمحتوى مختلف.");

                return ToMessage(previous);
            }

            if (conversation.CyberCaseId is not null ||
                conversation.FormalReportConsentAtUtc is not null ||
                conversation.Status is not (
                    IntakeConversationStatus.Assistant or
                    IntakeConversationStatus.AwaitingReportDecision))
                throw new InvalidOperationException(
                    "هذه المحادثة غير متاحة لإرسال رسائل استقبال جديدة.");

            if (await db.IntakeConversationMessages.CountAsync(
                x => x.ConversationId == conversationId, ct) >= 400)
                throw new InvalidOperationException(
                    "وصلت المحادثة للحد المتاح من الرسائل.");

            var lastSequence = await db.IntakeConversationMessages
                .Where(x => x.ConversationId == conversationId)
                .Select(x => (long?)x.SequenceNumber)
                .MaxAsync(ct) ?? 0;

            var now = DateTime.UtcNow;
            var message = new IntakeConversationMessage
            {
                ConversationId = conversationId,
                OperationId = operationId,
                SequenceNumber = checked(lastSequence + 1),
                Role = IntakeMessageRole.Reporter,
                AuthorUserId = reporterId,
                Content = text,
                CreatedAtUtc = now
            };

            db.IntakeConversationMessages.Add(message);
            conversation.UpdatedAtUtc = now;
            conversation.Status = IntakeConversationStatus.Assistant;

            await db.SaveChangesAsync(ct);
            return ToMessage(message);
        }, cancellationToken);
    }

    private async Task<Guid> RequireReporterAsync(
        AccpDbContext db,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var actor = await _authorization.GetCurrentActorAsync(ct);

        if (actor is null || !actor.HasRole(IdentityRoles.User))
            throw NoAccess();

        var account = await db.Users.AsNoTracking()
            .SingleOrDefaultAsync(x => x.Id == actor.UserId, ct);

        var roles = await db.UserRoles
            .Where(x => x.UserId == actor.UserId)
            .Join(
                db.Roles,
                x => x.RoleId,
                x => x.Id,
                (_, role) => role.Name)
            .ToListAsync(ct);

        if (account is null || !account.IsActive ||
            (account.LockoutEnabled &&
             account.LockoutEnd > DateTimeOffset.UtcNow) ||
            roles.Count != 1 || roles[0] != IdentityRoles.User)
            throw NoAccess();

        var confirmed = await _authorization.GetCurrentActorAsync(ct);

        if (confirmed?.UserId != actor.UserId ||
            !confirmed.HasRole(IdentityRoles.User))
            throw NoAccess();

        return actor.UserId;
    }

    private async Task<T> WriteAsync<T>(
        Func<AccpDbContext, Guid, CancellationToken, Task<T>> action,
        CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                await using var scope = _scopes.CreateAsyncScope();
                var db = scope.ServiceProvider
                    .GetRequiredService<AccpDbContext>();

                return await db.Database.CreateExecutionStrategy()
                    .ExecuteAsync(async () =>
                    {
                        await using var transaction =
                            await db.Database.BeginTransactionAsync(
                                IsolationLevel.Serializable, ct);

                        db.ChangeTracker.Clear();

                        var reporterId = await RequireReporterAsync(db, ct);
                        var result = await action(db, reporterId, ct);

                        await transaction.CommitAsync(ct);
                        return result;
                    });
            }
            catch (Exception exception) when (
                attempt < 2 && IsRetryableConflict(exception))
            {
                await Task.Delay(
                    TimeSpan.FromMilliseconds(40 * (attempt + 1)), ct);
            }
        }
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
            throw new ArgumentException("معرّف الطلب غير صالح.");
    }

    private static UnauthorizedAccessException NoAccess() =>
        new("تعذر الوصول إلى المحادثة.");

    private static IntakeConversationInfo ToInfo(
        IntakeConversation item) =>
        new(
            item.Id, item.Title, item.Status, item.CyberCaseId,
            item.CreatedAtUtc, item.UpdatedAtUtc);

    private static IntakeMessageInfo ToMessage(
        IntakeConversationMessage item) =>
        new(
            item.Id, item.SequenceNumber, item.Role, item.Content,
            item.OperationId, item.CreatedAtUtc);
}