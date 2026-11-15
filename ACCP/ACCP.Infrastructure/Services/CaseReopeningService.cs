using System.Data;
using ACCP.Application.Auditing;
using ACCP.Application.Cases;
using ACCP.Application.Notifications;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using Microsoft.EntityFrameworkCore;

namespace ACCP.Infrastructure.Services;

// Called through the Web authorization boundary with a server-derived actor ID.
// A fresh context and the same-context audit/notification writers are required.
public sealed class CaseReopeningService(
    AccpDbContext db,
    IAuditService audit,
    INotificationService notifications)
{
    public async Task<bool> ReopenAsync(
        CaseReopeningSnapshot expected,
        Guid targetOfficerId,
        Guid adminId,
        string reason,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expected);
        string cleanReason = reason?.Trim() ?? string.Empty;
        if (expected.CaseId == Guid.Empty || adminId == Guid.Empty ||
            targetOfficerId == Guid.Empty || expected.HistoryCount < 0 || cleanReason.Length is < 10 or > 1000 ||
            expected.Status is not (CaseStatus.Resolved or CaseStatus.Closed))
            return false;

        await using var transaction = await db.Database.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        try
        {
            var now = DateTime.UtcNow;
            var admin = await db.Users.AsNoTracking().SingleOrDefaultAsync(
                user => user.Id == adminId, cancellationToken);
            if (!Usable(admin) || !await HasRoleAsync(adminId, IdentityRoles.Admin))
                return false;
            var officer = await db.Users.AsNoTracking().SingleOrDefaultAsync(
                user => user.Id == targetOfficerId, cancellationToken);
            if (!Usable(officer) ||
                !await HasRoleAsync(targetOfficerId, IdentityRoles.Officer) ||
                await HasRoleAsync(targetOfficerId, IdentityRoles.Admin))
                return false;

            bool ownerChanged = expected.OfficerId != targetOfficerId;
            DateTime? assignedAt = ownerChanged ? now : expected.AssignedAtUtc ?? now;
            int affected = await db.CyberCases
                .Where(item => item.Id == expected.CaseId &&
                    item.Path == CasePath.FormalReport &&
                    item.Status == expected.Status &&
                    item.AssignedOfficerId == expected.OfficerId &&
                    item.AssignedAtUtc == expected.AssignedAtUtc &&
                    db.CaseStatusHistories.Count(history => history.CyberCaseId == item.Id) == expected.HistoryCount)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(item => item.Status, CaseStatus.InProgress)
                    .SetProperty(item => item.AssignedOfficerId, (Guid?)targetOfficerId)
                    .SetProperty(item => item.AssignedOfficerEmail, officer!.Email)
                    .SetProperty(item => item.AssignedAtUtc, assignedAt), cancellationToken);
            if (affected != 1) return false;

            var info = await db.CyberCases.AsNoTracking()
                .Where(item => item.Id == expected.CaseId)
                .Select(item => new { item.CaseNumber, item.ReporterId })
                .SingleAsync(cancellationToken);
            db.CaseStatusHistories.Add(new CaseStatusHistory
            {
                CyberCaseId = expected.CaseId,
                OldStatus = expected.Status,
                NewStatus = CaseStatus.InProgress,
                ChangedByUserId = adminId,
                ChangedByEmail = admin!.Email!,
                ChangedAtUtc = now,
                Reason = cleanReason
            });

            // A previous owner must not retain a duplicate participation grant.
            // Other collaborators retain their existing participation rights.
            var revoked = await db.CaseCollaborators
                .Where(item => item.CyberCaseId == expected.CaseId && item.IsActive &&
                    (item.OfficerId == targetOfficerId ||
                        (ownerChanged && item.OfficerId == expected.OfficerId)))
                .ToListAsync(cancellationToken);
            foreach (var entry in revoked)
            {
                entry.IsActive = false;
                entry.RemovedByAdminId = adminId;
                entry.RemovedByAdminEmail = admin!.Email;
                entry.RemovedAtUtc = now;
                entry.RemovalReason = entry.OfficerId == targetOfficerId
                    ? "أصبح الموظف مسؤولًا عن القضية عند إعادة فتحها."
                    : "انتهت مسؤولية الموظف السابق عند إعادة فتح القضية.";
            }

            var pending = await db.CaseStaffRequests
                .Where(item => item.CyberCaseId == expected.CaseId &&
                    item.Status == CaseStaffRequestStatus.Pending)
                .ToListAsync(cancellationToken);
            foreach (var request in pending)
            {
                request.Status = CaseStaffRequestStatus.Cancelled;
                request.ReviewedByAdminId = adminId;
                request.ReviewedByAdminEmail = admin!.Email;
                request.ReviewedAtUtc = now;
                request.DecisionNote = "أُلغي الطلب السابق عند إعادة فتح القضية إداريًا؛ يمكن تقديم طلب جديد.";
            }
            await db.SaveChangesAsync(cancellationToken);

            await WriteAuditAsync(AuditAction.CaseStatusChanged, nameof(CyberCase),
                expected.CaseId,
                $"أعاد المدير فتح القضية من {expected.Status} إلى InProgress. الموظف المسؤول: {targetOfficerId:D}. السبب محفوظ في سجل الحالة.");
            if (ownerChanged)
                await WriteAuditAsync(AuditAction.CaseAssignmentTransferred, nameof(CyberCase),
                    expected.CaseId, $"تغيّر المسؤول عند إعادة الفتح من {expected.OfficerId} إلى {targetOfficerId:D}.");
            foreach (var entry in revoked)
                await WriteAuditAsync(AuditAction.CaseCollaboratorRemoved, nameof(CaseCollaborator),
                    entry.Id, entry.RemovalReason!);
            foreach (var request in pending)
            {
                await WriteAuditAsync(AuditAction.CaseStaffRequestCancelled, nameof(CaseStaffRequest),
                    request.Id, "أُلغي طلب الموظفين السابق عند إعادة فتح القضية إداريًا.");
                if (await db.Users.AnyAsync(user => user.Id == request.RequestedByOfficerId, cancellationToken))
                    await notifications.CreateAsync(request.RequestedByOfficerId, null,
                        NotificationType.CaseStaffRequestCancelled, "أُلغي طلب الموظفين السابق",
                        $"أُلغي طلبك السابق للقضية {info.CaseNumber} عند إعادة فتحها إداريًا.");
            }
            await notifications.CreateAsync(targetOfficerId, expected.CaseId,
                NotificationType.CaseStatusChanged, "أُعيد فتح قضية لمتابعتها",
                $"أصبحت القضية {info.CaseNumber} قيد المعالجة وأنت الموظف المسؤول عنها.");
            if (info.ReporterId is { } reporter && reporter != Guid.Empty &&
                await db.Users.AnyAsync(user => user.Id == reporter, cancellationToken))
                await notifications.CreateAsync(reporter, expected.CaseId,
                    NotificationType.CaseStatusChanged, "أُعيد فتح بلاغك",
                    $"أُعيد فتح البلاغ {info.CaseNumber} وأصبح قيد المعالجة.");
            if (ownerChanged && expected.OfficerId is { } previous &&
                await db.Users.AnyAsync(user => user.Id == previous, cancellationToken))
                await notifications.CreateAsync(previous, null,
                    NotificationType.CaseAssignmentTransferred, "تغيّرت مسؤولية قضية",
                    $"أُعيد فتح القضية {info.CaseNumber} وأُسندت إلى موظف آخر.");

            await transaction.CommitAsync(cancellationToken);
            return true;

            Task<bool> HasRoleAsync(Guid userId, string roleName) => db.UserRoles
                .Where(member => member.UserId == userId)
                .Join(db.Roles, member => member.RoleId, role => role.Id, (_, role) => role.Name)
                .AnyAsync(name => name == roleName, cancellationToken);

            Task<AuditLog> WriteAuditAsync(AuditAction action, string entityType,
                Guid entityId, string description) => audit.WriteAsync(new AuditLogRequest
                {
                    Action = action, ActorUserId = adminId, ActorEmail = admin!.Email!,
                    ActorRole = IdentityRoles.Admin, CyberCaseId = expected.CaseId,
                    EntityType = entityType, EntityId = entityId,
                    Description = description, IsSuccessful = true
                }, cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None);
            throw;
        }
    }

    private static bool Usable(ApplicationUser? user) =>
        user is { IsActive: true } && !string.IsNullOrWhiteSpace(user.Email) &&
        (!user.LockoutEnabled || user.LockoutEnd is null ||
            user.LockoutEnd <= DateTimeOffset.UtcNow);
}
