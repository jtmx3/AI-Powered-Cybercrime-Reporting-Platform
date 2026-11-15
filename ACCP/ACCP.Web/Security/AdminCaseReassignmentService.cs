using System.Data;
using System.Data.Common;
using ACCP.Application.Auditing;
using ACCP.Application.Notifications;
using ACCP.Application.Security;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace ACCP.Web.Security;

public sealed record AdminCaseAssignmentSnapshot(
    Guid CaseId,
    string CaseNumber,
    Guid OfficerId,
    CaseStatus Status,
    DateTime? AssignedAtUtc);

public sealed record AdminCaseReassignmentResult(
    bool Succeeded,
    string Message);

public sealed class AdminCaseReassignmentService
{
    private readonly CaseAuthorizationService _authorization;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<AdminCaseReassignmentService> _logger;

    public AdminCaseReassignmentService(
        CaseAuthorizationService authorization,
        IServiceScopeFactory scopeFactory,
        ILogger<AdminCaseReassignmentService> logger)
    {
        _authorization = authorization;
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    public async Task<AdminCaseAssignmentSnapshot?> GetCaseAsync(
        Guid caseId,
        CancellationToken cancellationToken = default)
    {
        await RequireAdminAsync(cancellationToken);

        if (caseId == Guid.Empty)
            return null;

        await using var scope = _scopeFactory.CreateAsyncScope();

        var db = scope.ServiceProvider
            .GetRequiredService<AccpDbContext>();

        return await db.CyberCases
            .AsNoTracking()
            .Where(item =>
                item.Id == caseId &&
                item.Path == CasePath.FormalReport &&
                item.AssignedOfficerId.HasValue &&
                item.Status != CaseStatus.Resolved &&
                item.Status != CaseStatus.Closed)
            .Select(item => new AdminCaseAssignmentSnapshot(
                item.Id,
                item.CaseNumber,
                item.AssignedOfficerId!.Value,
                item.Status,
                item.AssignedAtUtc))
            .SingleOrDefaultAsync(cancellationToken);
    }

    public async Task<AdminCaseReassignmentResult> ReassignAsync(
        AdminCaseAssignmentSnapshot? expected,
        Guid targetOfficerId,
        string reason,
        CancellationToken cancellationToken = default)
    {
        var actor = await RequireAdminAsync(cancellationToken);

        var cleanReason = reason?.Trim() ?? string.Empty;

        if (expected is null ||
            expected.CaseId == Guid.Empty ||
            expected.OfficerId == Guid.Empty ||
            targetOfficerId == Guid.Empty ||
            targetOfficerId == expected.OfficerId ||
            !Enum.IsDefined(expected.Status) ||
            expected.Status is CaseStatus.Resolved or CaseStatus.Closed)
        {
            return Failure(
                "اختر قضية مفتوحة وموظفًا بديلًا " +
                "مختلفًا عن المسؤول الحالي.");
        }

        if (cleanReason.Length is < 10 or > 500 ||
            cleanReason.Any(char.IsControl))
        {
            return Failure(
                "اكتب سبب النقل من 10 إلى 500 حرف في سطر واحد.");
        }

        await using var scope = _scopeFactory.CreateAsyncScope();

        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<AccpDbContext>();
        var audit = services.GetRequiredService<IAuditService>();

        var notifications =
            services.GetRequiredService<INotificationService>();

        await using var transaction =
            await db.Database.BeginTransactionAsync(
                IsolationLevel.Serializable,
                cancellationToken);

        try
        {
            var target = await db.Users
                .AsNoTracking()
                .Where(user =>
                    user.Id == targetOfficerId &&
                    user.IsActive)
                .Select(user => new
                {
                    user.Id,
                    user.Email,
                    user.LockoutEnabled,
                    user.LockoutEnd
                })
                .SingleOrDefaultAsync(cancellationToken);

            var now = DateTime.UtcNow;

            if (target is null ||
                string.IsNullOrWhiteSpace(target.Email) ||
                (target.LockoutEnabled &&
                 target.LockoutEnd is { } end &&
                 end > DateTimeOffset.UtcNow))
            {
                return Failure(
                    "اختر موظفًا مفعّلًا وغير مقفل مؤقتًا.");
            }

            var targetRoles = await db.UserRoles
                .Where(member =>
                    member.UserId == targetOfficerId)
                .Join(
                    db.Roles,
                    member => member.RoleId,
                    role => role.Id,
                    (_, role) => role.Name)
                .ToListAsync(cancellationToken);

            if (!targetRoles.Contains(IdentityRoles.Officer) ||
                targetRoles.Contains(IdentityRoles.Admin))
            {
                return Failure(
                    "الموظف البديل يجب أن يحمل دور موظف؛ " +
                    "حسابات المديرين محمية.");
            }

            // التحقق من أن الإسناد والحالة لم يتغيرا
            // منذ تحميل بيانات صفحة التأكيد.
            var updated = await db.CyberCases
                .Where(item =>
                    item.Id == expected.CaseId &&
                    item.Path == CasePath.FormalReport &&
                    item.AssignedOfficerId == expected.OfficerId &&
                    item.AssignedAtUtc == expected.AssignedAtUtc &&
                    item.Status == expected.Status &&
                    item.Status != CaseStatus.Resolved &&
                    item.Status != CaseStatus.Closed)
                .ExecuteUpdateAsync(
                    setters => setters
                        .SetProperty(
                            item => item.AssignedOfficerId,
                            (Guid?)target.Id)
                        .SetProperty(
                            item => item.AssignedOfficerEmail,
                            target.Email)
                        .SetProperty(
                            item => item.AssignedAtUtc,
                            (DateTime?)now),
                    cancellationToken);

            if (updated != 1)
            {
                return Failure(
                    "تغيّر إسناد القضية أو حالتها. " +
                    "حدّث البيانات قبل إعادة المحاولة.");
            }

            var caseInfo = await db.CyberCases
                .AsNoTracking()
                .Where(item => item.Id == expected.CaseId)
                .Select(item => new
                {
                    item.CaseNumber,
                    item.ReporterId
                })
                .SingleAsync(cancellationToken);

            var adminEmail = await db.Users
                .AsNoTracking()
                .Where(user => user.Id == actor.UserId)
                .Select(user => user.Email)
                .SingleOrDefaultAsync(cancellationToken);

            if (string.IsNullOrWhiteSpace(adminEmail))
            {
                throw new UnauthorizedAccessException(
                    "تعذر التحقق من حساب المدير.");
            }

            // إزالة أي مشاركة إضافية للمسؤول السابق،
            // وتحويل مشاركة الموظف الجديد إلى مسؤولية مباشرة.
            var collaborations = await db.CaseCollaborators
                .Where(item =>
                    item.CyberCaseId == expected.CaseId &&
                    item.IsActive &&
                    (item.OfficerId == expected.OfficerId ||
                     item.OfficerId == target.Id))
                .ToListAsync(cancellationToken);

            foreach (var item in collaborations)
            {
                item.IsActive = false;
                item.RemovedByAdminId = actor.UserId;
                item.RemovedByAdminEmail = adminEmail;
                item.RemovedAtUtc = now;

                item.RemovalReason = item.OfficerId == target.Id
                    ? "أصبح الموظف مسؤولًا عن القضية بالنقل الإداري."
                    : "انتهت مسؤولية الموظف عن القضية بالنقل الإداري.";
            }

            // إلغاء الطلبات المعلقة المرتبطة بالإسناد السابق.
            var pending = await db.CaseStaffRequests
                .Where(item =>
                    item.CyberCaseId == expected.CaseId &&
                    item.Status == CaseStaffRequestStatus.Pending)
                .ToListAsync(cancellationToken);

            foreach (var request in pending)
            {
                request.Status = CaseStaffRequestStatus.Cancelled;
                request.ReviewedByAdminId = actor.UserId;
                request.ReviewedByAdminEmail = adminEmail;
                request.ReviewedAtUtc = now;

                request.DecisionNote =
                    $"أُلغي الطلب بسبب النقل الإداري. السبب: {cleanReason}";
            }

            await db.SaveChangesAsync(cancellationToken);

            foreach (var item in collaborations)
            {
                await WriteAuditAsync(
                    AuditAction.CaseCollaboratorRemoved,
                    nameof(CaseCollaborator),
                    item.Id,
                    item.RemovalReason!);
            }

            foreach (var request in pending)
            {
                await WriteAuditAsync(
                    AuditAction.CaseStaffRequestCancelled,
                    nameof(CaseStaffRequest),
                    request.Id,
                    "أُلغي طلب الموظفين المعلّق بسبب " +
                    "تغيير مسؤول القضية إداريًا.");

                var requesterExists = await db.Users.AnyAsync(
                    user => user.Id == request.RequestedByOfficerId,
                    cancellationToken);

                if (requesterExists)
                {
                    await notifications.CreateAsync(
                        request.RequestedByOfficerId,
                        null,
                        NotificationType.CaseStaffRequestCancelled,
                        "أُلغي طلب الموظفين",
                        $"أُلغي طلبك المرتبط بالقضية {caseInfo.CaseNumber} " +
                        "بسبب تغيير مسؤولها إداريًا.");
                }
            }

            await notifications.CreateAsync(
                target.Id,
                expected.CaseId,
                NotificationType.CaseAssignmentTransferred,
                "تم نقل قضية إليك",
                $"أصبحت مسؤولًا عن القضية {caseInfo.CaseNumber} " +
                "بقرار من المدير.");

            var previousOfficerExists = await db.Users.AnyAsync(
                user => user.Id == expected.OfficerId,
                cancellationToken);

            if (previousOfficerExists)
            {
                await notifications.CreateAsync(
                    expected.OfficerId,
                    null,
                    NotificationType.CaseAssignmentTransferred,
                    "تم نقل مسؤولية قضية",
                    $"نقل المدير مسؤولية القضية {caseInfo.CaseNumber} " +
                    "إلى موظف آخر.");
            }

            if (caseInfo.ReporterId is { } reporterId &&
                reporterId != Guid.Empty &&
                await db.Users.AnyAsync(
                    user => user.Id == reporterId,
                    cancellationToken))
            {
                await notifications.CreateAsync(
                    reporterId,
                    expected.CaseId,
                    NotificationType.CaseAssignmentTransferred,
                    "تحديث متابعة البلاغ",
                    $"تم تحديث الموظف المسؤول عن بلاغك " +
                    $"{caseInfo.CaseNumber}. سجل البلاغ محفوظ.");
            }

            await WriteAuditAsync(
                AuditAction.CaseAssignmentTransferred,
                nameof(CyberCase),
                expected.CaseId,
                $"نقل المدير المسؤولية من الموظف {expected.OfficerId:D} " +
                $"إلى {target.Id:D}. السبب: {cleanReason}");

            var current = await RequireAdminAsync(cancellationToken);

            if (current.UserId != actor.UserId)
            {
                throw new UnauthorizedAccessException(
                    "تغيّرت جلسة المدير أثناء النقل.");
            }

            await transaction.CommitAsync(cancellationToken);

            return new AdminCaseReassignmentResult(
                true,
                "تم نقل مسؤولية القضية وتسجيل العملية وإرسال الإشعارات.");

            Task<AuditLog> WriteAuditAsync(
                AuditAction action,
                string entityType,
                Guid entityId,
                string description) =>
                audit.WriteAsync(
                    new AuditLogRequest
                    {
                        Action = action,
                        ActorUserId = actor.UserId,
                        ActorEmail = adminEmail,
                        ActorRole = IdentityRoles.Admin,
                        CyberCaseId = expected.CaseId,
                        EntityType = entityType,
                        EntityId = entityId,
                        Description = description,
                        IsSuccessful = true
                    },
                    cancellationToken);
        }
        catch (Exception exception)
            when (exception is DbException or DbUpdateException)
        {
            _logger.LogWarning(
                "Administrative transfer outcome unavailable. Category: {Category}",
                exception.GetType().Name);

            try
            {
                await transaction.RollbackAsync(CancellationToken.None);
            }
            catch (Exception rollbackException)
                when (rollbackException is DbException or InvalidOperationException)
            {
                _logger.LogWarning(
                    "Administrative transfer rollback unavailable. Category: {Category}",
                    rollbackException.GetType().Name);
            }

            return Failure(
                "تعذر تأكيد نتيجة النقل. حدّث القائمة وتحقق من " +
                "المسؤول الحالي قبل المحاولة مجددًا.");
        }
    }

    private async Task<CaseAccessActor> RequireAdminAsync(
        CancellationToken cancellationToken)
    {
        var actor = await _authorization.GetCurrentActorAsync(
            cancellationToken);

        if (actor is null ||
            !actor.IsAuthenticated ||
            !actor.IsActive ||
            actor.UserId == Guid.Empty ||
            !actor.HasRole(IdentityRoles.Admin))
        {
            throw new UnauthorizedAccessException(
                "النقل الإداري متاح لمدير فعّال " +
                "أكمل التحقق الثنائي فقط.");
        }

        return actor;
    }

    private static AdminCaseReassignmentResult Failure(
        string message) =>
        new(false, message);
}