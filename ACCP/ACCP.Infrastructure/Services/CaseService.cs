using ACCP.Application.Auditing;
using ACCP.Application.Cases;
using ACCP.Application.Notifications;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
namespace ACCP.Infrastructure.Services;
public class CaseService : ICaseService
{
    private readonly AccpDbContext _dbContext;
    private readonly IAuditService _auditService;
    private readonly INotificationService _notificationService;
    public CaseService(
        AccpDbContext dbContext,
        IAuditService auditService,
        INotificationService notificationService)
    {
        _dbContext = dbContext;
        _auditService = auditService;
        _notificationService = notificationService;
    }
    public async Task<CyberCase> CreateForReporterAsync(
        CyberCase cyberCase,
        Guid reporterId)
    {
        ArgumentNullException.ThrowIfNull(cyberCase);
        if (reporterId == Guid.Empty)
        {
            throw new ArgumentException(
                "معرّف المستخدم غير صالح.",
                nameof(reporterId));
        }
        if (!Enum.IsDefined(cyberCase.Path))
        {
            throw new ArgumentException(
                "مسار القضية غير صالح.",
                nameof(cyberCase));
        }
        return await ExecuteCaseTransactionAsync<CyberCase>(async () =>
        {
            cyberCase.ReporterId = reporterId;
            cyberCase.CreatedAtUtc = DateTime.UtcNow;
            if (string.IsNullOrWhiteSpace(cyberCase.CaseNumber))
            {
                cyberCase.CaseNumber =
                    $"ACCP-{cyberCase.CreatedAtUtc:yyyyMMdd}-{Guid.NewGuid():N}";
            }
            _dbContext.CyberCases.Add(cyberCase);
            await _auditService.WriteAsync(
                new AuditLogRequest
                {
                    Action = AuditAction.CaseCreated,
                    ActorUserId = reporterId,
                    ActorRole = "USER",
                    CyberCaseId = cyberCase.Id,
                    EntityType = nameof(CyberCase),
                    EntityId = cyberCase.Id,
                    Description =
                        $"تم إنشاء القضية رقم {cyberCase.CaseNumber}.",
                    IsSuccessful = true
                });
            return cyberCase;
        });
    }
    public async Task<List<CyberCase>> GetAllForReporterAsync(
        Guid reporterId)
    {
        if (reporterId == Guid.Empty)
        {
            return [];
        }
        return await _dbContext.CyberCases
            .AsNoTracking()
            .Where(cyberCase =>
                cyberCase.ReporterId == reporterId)
            .OrderByDescending(cyberCase =>
                cyberCase.CreatedAtUtc)
            .ToListAsync();
    }
    public async Task<CyberCase?> GetByIdForReporterAsync(
        Guid id,
        Guid reporterId)
    {
        if (id == Guid.Empty ||
            reporterId == Guid.Empty)
        {
            return null;
        }
        return await _dbContext.CyberCases
            .AsNoTracking()
            .Include(cyberCase =>
    cyberCase.EvidenceItems)
.ThenInclude(evidence =>
    evidence.Revisions
        .OrderBy(revision =>
            revision.VersionNumber))
            .Include(cyberCase =>
                cyberCase.Messages
                    .OrderBy(message =>
                        message.CreatedAtUtc))
            .AsSplitQuery()
            .FirstOrDefaultAsync(cyberCase =>
                cyberCase.Id == id &&
                cyberCase.ReporterId == reporterId);
    }
    public async Task<List<CyberCase>> GetAllForOfficerAsync()
    {
        return await _dbContext.CyberCases
            .AsNoTracking()
            .Where(cyberCase =>
                cyberCase.Path == CasePath.FormalReport)
            .Include(cyberCase =>
                cyberCase.EvidenceItems)
            .Include(cyberCase =>
                cyberCase.Collaborators.Where(collaborator =>
                    collaborator.IsActive))
            .AsSplitQuery()
            .OrderByDescending(cyberCase =>
                cyberCase.CreatedAtUtc)
            .ToListAsync();
    }
  public async Task<CyberCase?> GetByIdForOfficerAsync(
    Guid id,
    Guid officerId)
{
    if (id == Guid.Empty ||
        officerId == Guid.Empty)
    {
        return null;
    }
    return await BuildOfficerCaseQuery(
            includeRestrictedEvidence: false)
        .FirstOrDefaultAsync(cyberCase =>
            cyberCase.Id == id &&
            (!cyberCase.AssignedOfficerId.HasValue ||
             cyberCase.AssignedOfficerId == officerId ||
             cyberCase.Collaborators.Any(collaborator =>
                 collaborator.OfficerId == officerId &&
                 collaborator.IsActive)));
}
public async Task<CyberCase?> GetByIdForAdminAsync(
    Guid id)
{
    if (id == Guid.Empty)
    {
        return null;
    }
    return await BuildOfficerCaseQuery(
            includeRestrictedEvidence: true)
        .FirstOrDefaultAsync(cyberCase =>
            cyberCase.Id == id);
}
private IQueryable<CyberCase> BuildOfficerCaseQuery(
    bool includeRestrictedEvidence)
{
    IQueryable<CyberCase> query =
        _dbContext.CyberCases
            .AsNoTracking()
            .Where(cyberCase =>
                cyberCase.Path == CasePath.FormalReport);
if (includeRestrictedEvidence)
{
    query = query
        .Include(cyberCase =>
            cyberCase.EvidenceItems)
        .ThenInclude(evidence =>
            evidence.Revisions
                .OrderBy(revision =>
                    revision.VersionNumber));
}
else
{
    query = query
        .Include(cyberCase =>
            cyberCase.EvidenceItems.Where(evidence =>
                !evidence.IsRestricted ||
                evidence.IsDisclosedToOfficer))
        .ThenInclude(evidence =>
            evidence.Revisions
                .OrderBy(revision =>
                    revision.VersionNumber));
}
    return query
        .Include(cyberCase =>
            cyberCase.StatusHistory
                .OrderByDescending(history =>
                    history.ChangedAtUtc))
        .Include(cyberCase =>
            cyberCase.InternalNotes
                .OrderByDescending(note =>
                    note.CreatedAtUtc))
        .Include(cyberCase =>
            cyberCase.Messages
                .OrderBy(message =>
                    message.CreatedAtUtc))
        .Include(cyberCase =>
            cyberCase.Collaborators.Where(collaborator =>
                collaborator.IsActive))
        .AsSplitQuery();
}
    public async Task<bool> UpdateStatusForOfficerAsync(
        Guid id,
        CaseStatus newStatus,
        Guid officerId,
        string officerEmail,
        string? reason = null)
    {
        if (id == Guid.Empty ||
            officerId == Guid.Empty ||
            string.IsNullOrWhiteSpace(officerEmail) ||
            !Enum.IsDefined(newStatus))
        {
            return false;
        }
        return await ExecuteCaseTransactionAsync<bool>(async () =>
        {
            CyberCase? cyberCase =
                await _dbContext.CyberCases
                    .AsNoTracking()
                    .FirstOrDefaultAsync(cyberCase =>
                        cyberCase.Id == id &&
                        cyberCase.Path == CasePath.FormalReport);
            if (cyberCase is null)
            {
                return false;
            }
            if (cyberCase.AssignedOfficerId != officerId)
            {
                return false;
            }
            CaseStatus oldStatus = cyberCase.Status;
            if (oldStatus == newStatus)
            {
                RefreshTrackedCaseStatus(id, newStatus);
                return true;
            }
            if (!ACCP.Domain.Policies.CaseStatusWorkflow.CanTransition(
                    oldStatus, newStatus))
            {
                return false;
            }

            string? cleanReason = string.IsNullOrWhiteSpace(reason)
                ? null : reason.Trim();
            bool requiresReason = newStatus is CaseStatus.Resolved or CaseStatus.Closed;
            if ((requiresReason && cleanReason is null) ||
                (cleanReason is not null &&
                    (cleanReason.Length < 10 || cleanReason.Length > 1000)))
            {
                return false;
            }

            // Change the status only if ownership and the status read above
            // still match. A competing update must not produce stale history.
            int affectedRows = await _dbContext.CyberCases
                .Where(item => item.Id == id &&
                    item.Path == CasePath.FormalReport &&
                    item.AssignedOfficerId == officerId &&
                    item.Status == oldStatus)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(item => item.Status, newStatus));
            if (affectedRows != 1)
            {
                return false;
            }

            RefreshTrackedCaseStatus(id, newStatus);
            var history = new CaseStatusHistory
            {
                CyberCaseId = cyberCase.Id,
                OldStatus = oldStatus,
                NewStatus = newStatus,
                ChangedByUserId = officerId,
                ChangedByEmail = officerEmail.Trim(),
                Reason = cleanReason,
                ChangedAtUtc = DateTime.UtcNow
            };
            _dbContext.CaseStatusHistories.Add(history);
            await _auditService.WriteAsync(
                new AuditLogRequest
                {
                    Action = AuditAction.CaseStatusChanged,
                    ActorUserId = officerId,
                    ActorEmail = officerEmail.Trim(),
                    ActorRole = "OFFICER",
                    CyberCaseId = cyberCase.Id,
                    EntityType = nameof(CyberCase),
                    EntityId = cyberCase.Id,
                    Description =
                        $"تم تغيير حالة القضية من {oldStatus} إلى {newStatus}.",
                    IsSuccessful = true
                });
            if (cyberCase.ReporterId.HasValue)
            {
                await _notificationService.CreateAsync(
                    cyberCase.ReporterId.Value,
                    cyberCase.Id,
                    NotificationType.CaseStatusChanged,
                    "تحديث على القضية",
                    "تم تحديث حالة إحدى قضاياك. افتح القضية للاطلاع على الحالة الجديدة.");
            }
            return true;
        });
    }
    // ExecuteUpdate bypasses tracking. Keep the status current so a later
    // SaveChanges cannot write a stale status back into the case.
    private void RefreshTrackedCaseStatus(Guid id, CaseStatus status)
    {
        var entry = _dbContext.ChangeTracker.Entries<CyberCase>()
            .FirstOrDefault(item => item.Entity.Id == id);
        if (entry is null)
        {
            return;
        }
        var statusProperty = entry.Property(item => item.Status);
        statusProperty.CurrentValue = status;
        statusProperty.OriginalValue = status;
        statusProperty.IsModified = false;
    }

    public async Task<bool> AssignToOfficerAsync(
        Guid id,
        Guid officerId,
        string officerEmail)
    {
        if (id == Guid.Empty ||
            officerId == Guid.Empty ||
            string.IsNullOrWhiteSpace(officerEmail) ||
            officerEmail.Trim().Length > 256)
        {
            return false;
        }

        await using var transaction =
            await _dbContext.Database.BeginTransactionAsync();

        try
        {
            CyberCase? cyberCase =
                await _dbContext.CyberCases
                    .AsNoTracking()
                    .FirstOrDefaultAsync(item =>
                        item.Id == id &&
                        item.Path == CasePath.FormalReport);

            if (cyberCase is null)
            {
                return false;
            }

            // Repeating a completed claim must not duplicate its audit or notification.
            if (cyberCase.AssignedOfficerId.HasValue)
            {
                return cyberCase.AssignedOfficerId == officerId;
            }

            string cleanOfficerEmail = officerEmail.Trim();
            DateTime assignedAtUtc = DateTime.UtcNow;

            // This conditional UPDATE is the claim. Only one officer can change
            // AssignedOfficerId from NULL; another claimant gets zero affected rows.
            int affectedRows = await _dbContext.CyberCases
                .Where(item => item.Id == id &&
                    item.Path == CasePath.FormalReport &&
                    !item.AssignedOfficerId.HasValue)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(item => item.AssignedOfficerId, (Guid?)officerId)
                    .SetProperty(item => item.AssignedOfficerEmail, cleanOfficerEmail)
                    .SetProperty(item => item.AssignedAtUtc, (DateTime?)assignedAtUtc)
                    .SetProperty(item => item.Status, item =>
                        item.Status == CaseStatus.New || item.Status == CaseStatus.UnderReview
                            ? CaseStatus.Assigned
                            : item.Status));

            if (affectedRows != 1)
            {
                return false;
            }

            CaseStatus oldStatus = cyberCase.Status;
            if (oldStatus == CaseStatus.New || oldStatus == CaseStatus.UnderReview)
            {
                _dbContext.CaseStatusHistories.Add(new CaseStatusHistory
                {
                    CyberCaseId = id,
                    OldStatus = oldStatus,
                    NewStatus = CaseStatus.Assigned,
                    ChangedByUserId = officerId,
                    ChangedByEmail = cleanOfficerEmail,
                    ChangedAtUtc = assignedAtUtc
                });
            }

            // Both services use the same scoped DbContext, so their saves
            // remain inside this transaction until all three operations succeed.
            await _auditService.WriteAsync(new AuditLogRequest
            {
                Action = AuditAction.CaseAssigned,
                ActorUserId = officerId,
                ActorEmail = cleanOfficerEmail,
                ActorRole = "OFFICER",
                CyberCaseId = id,
                EntityType = nameof(CyberCase),
                EntityId = id,
                Description = "تم استلام القضية وتعيين الموظف المسؤول عنها.",
                IsSuccessful = true
            });

            if (cyberCase.ReporterId.HasValue)
            {
                await _notificationService.CreateAsync(
                    cyberCase.ReporterId.Value,
                    id,
                    NotificationType.CaseAssigned,
                    "تم استلام القضية",
                    "تم تعيين موظف مختص لمتابعة إحدى قضاياك.");
            }

            await _dbContext.SaveChangesAsync();
            await transaction.CommitAsync();

            // ExecuteUpdate bypasses tracking. Refresh any already-tracked case
            // to prevent a later operation from using its old assignment.
            var trackedCase = _dbContext.ChangeTracker.Entries<CyberCase>()
                .FirstOrDefault(entry => entry.Entity.Id == id);
            if (trackedCase is not null)
            {
                trackedCase.Entity.AssignedOfficerId = officerId;
                trackedCase.Entity.AssignedOfficerEmail = cleanOfficerEmail;
                trackedCase.Entity.AssignedAtUtc = assignedAtUtc;
                if (oldStatus == CaseStatus.New || oldStatus == CaseStatus.UnderReview)
                {
                    trackedCase.Entity.Status = CaseStatus.Assigned;
                }
                trackedCase.OriginalValues.SetValues(trackedCase.CurrentValues);
            }

            return true;
        }
        catch
        {
            await transaction.RollbackAsync();
            // A Blazor circuit may reuse this context after failure. Remove
            // rolled-back entries so a later save cannot resurrect them.
            _dbContext.ChangeTracker.Clear();
            throw;
        }
    }
    public async Task<CaseNote?> AddInternalNoteForOfficerAsync(
        Guid cyberCaseId,
        string content,
        Guid officerId,
        string officerEmail)
    {
        if (cyberCaseId == Guid.Empty ||
            officerId == Guid.Empty ||
            string.IsNullOrWhiteSpace(content) ||
            string.IsNullOrWhiteSpace(officerEmail))
        {
            return null;
        }
        string cleanContent = content.Trim();
        if (cleanContent.Length > 2000)
        {
            return null;
        }
        return await ExecuteCaseTransactionAsync<CaseNote?>(async () =>
        {
            CyberCase? cyberCase =
                await _dbContext.CyberCases
                    .FirstOrDefaultAsync(cyberCase =>
                        cyberCase.Id == cyberCaseId &&
                        cyberCase.Path == CasePath.FormalReport &&
                        (cyberCase.AssignedOfficerId == officerId ||
                         cyberCase.Collaborators.Any(collaborator =>
                             collaborator.OfficerId == officerId &&
                             collaborator.IsActive)));
            if (cyberCase is null)
            {
                return null;
            }
            var note = new CaseNote
            {
                CyberCaseId = cyberCase.Id,
                Content = cleanContent,
                OfficerId = officerId,
                OfficerEmail = officerEmail.Trim(),
                CreatedAtUtc = DateTime.UtcNow
            };
            _dbContext.Set<CaseNote>().Add(note);
            await _auditService.WriteAsync(new AuditLogRequest
            {
                Action = AuditAction.InternalNoteAdded,
                ActorUserId = officerId,
                ActorEmail = officerEmail.Trim(),
                ActorRole = "OFFICER",
                CyberCaseId = cyberCase.Id,
                EntityType = nameof(CaseNote),
                EntityId = note.Id,
                Description = "تمت إضافة ملاحظة داخلية للقضية.",
                IsSuccessful = true
            });
            return note;
        });
    }
    public async Task<CaseMessage?> SendMessageByReporterAsync(
        Guid cyberCaseId,
        string content,
        Guid reporterId,
        string reporterEmail)
    {
        if (cyberCaseId == Guid.Empty ||
            reporterId == Guid.Empty ||
            string.IsNullOrWhiteSpace(content) ||
            string.IsNullOrWhiteSpace(reporterEmail))
        {
            return null;
        }
        string cleanContent = content.Trim();
        if (cleanContent.Length > 4000)
        {
            return null;
        }
        return await ExecuteCaseTransactionAsync<CaseMessage?>(async () =>
        {
            CyberCase? cyberCase =
                await _dbContext.CyberCases
                    .FirstOrDefaultAsync(cyberCase =>
                        cyberCase.Id == cyberCaseId &&
                        cyberCase.Path == CasePath.FormalReport &&
                        cyberCase.ReporterId == reporterId);
            if (cyberCase is null ||
                !cyberCase.AssignedOfficerId.HasValue)
            {
                return null;
            }
            var message = new CaseMessage
            {
                CyberCaseId = cyberCase.Id,
                Content = cleanContent,
                SenderId = reporterId,
                SenderEmail = reporterEmail.Trim(),
                SenderType = MessageSenderType.User,
                CreatedAtUtc = DateTime.UtcNow
            };
            _dbContext.CaseMessages.Add(message);
            await _auditService.WriteAsync(new AuditLogRequest
            {
                Action = AuditAction.CaseMessageSent,
                ActorUserId = reporterId,
                ActorEmail = reporterEmail.Trim(),
                ActorRole = "USER",
                CyberCaseId = cyberCase.Id,
                EntityType = nameof(CaseMessage),
                EntityId = message.Id,
                Description = "أرسل المشتكي رسالة في القضية.",
                IsSuccessful = true
            });
            // يصل الإشعار إلى الموظف المسؤول وجميع المشاركين الفعّالين.
            List<Guid> staffRecipientIds =
                await _dbContext.CaseCollaborators
                    .AsNoTracking()
                    .Where(collaborator =>
                        collaborator.CyberCaseId == cyberCase.Id &&
                        collaborator.IsActive)
                    .Select(collaborator =>
                        collaborator.OfficerId)
                    .ToListAsync();

            staffRecipientIds.Add(
                cyberCase.AssignedOfficerId.Value);

            foreach (Guid recipientId in staffRecipientIds.Distinct())
            {
                await _notificationService.CreateAsync(
                    recipientId,
                    cyberCase.Id,
                    NotificationType.NewMessage,
                    "رسالة جديدة",
                    "وصلت رسالة جديدة في قضية تشارك في متابعتها.");
            }
            return message;
        });
    }
    public async Task<CaseMessage?> SendMessageByOfficerAsync(
        Guid cyberCaseId,
        string content,
        Guid officerId,
        string officerEmail)
    {
        if (cyberCaseId == Guid.Empty ||
            officerId == Guid.Empty ||
            string.IsNullOrWhiteSpace(content) ||
            string.IsNullOrWhiteSpace(officerEmail))
        {
            return null;
        }
        string cleanContent = content.Trim();
        if (cleanContent.Length > 4000)
        {
            return null;
        }
        return await ExecuteCaseTransactionAsync<CaseMessage?>(async () =>
        {
            CyberCase? cyberCase =
                await _dbContext.CyberCases
                    .FirstOrDefaultAsync(cyberCase =>
                        cyberCase.Id == cyberCaseId &&
                        cyberCase.Path == CasePath.FormalReport &&
                        (cyberCase.AssignedOfficerId == officerId ||
                         cyberCase.Collaborators.Any(collaborator =>
                             collaborator.OfficerId == officerId &&
                             collaborator.IsActive)));
            if (cyberCase is null)
            {
                return null;
            }
            var message = new CaseMessage
            {
                CyberCaseId = cyberCase.Id,
                Content = cleanContent,
                SenderId = officerId,
                SenderEmail = officerEmail.Trim(),
                SenderType = MessageSenderType.Officer,
                CreatedAtUtc = DateTime.UtcNow
            };
            _dbContext.CaseMessages.Add(message);
            await _auditService.WriteAsync(new AuditLogRequest
            {
                Action = AuditAction.CaseMessageSent,
                ActorUserId = officerId,
                ActorEmail = officerEmail.Trim(),
                ActorRole = "OFFICER",
                CyberCaseId = cyberCase.Id,
                EntityType = nameof(CaseMessage),
                EntityId = message.Id,
                Description = "أرسل موظف مشارك في القضية رسالة للمشتكي.",
                IsSuccessful = true
            });
            // الموظف أرسل رسالة، لذلك الإشعار يذهب إلى صاحب القضية.
            if (cyberCase.ReporterId.HasValue)
            {
                await _notificationService.CreateAsync(
                    cyberCase.ReporterId.Value,
                    cyberCase.Id,
                    NotificationType.NewMessage,
                    "رسالة جديدة",
                    "وصلتك رسالة جديدة من الموظف المختص بشأن إحدى قضاياك.");
            }
            return message;
        });
    }
    public async Task<bool> DiscloseReporterIdentityAsync(
        Guid cyberCaseId,
        Guid reporterId)
    {
        if (cyberCaseId == Guid.Empty ||
            reporterId == Guid.Empty)
        {
            return false;
        }
        return await ExecuteCaseTransactionAsync<bool>(async () =>
        {
            CyberCase? cyberCase =
                await _dbContext.CyberCases
                    .FirstOrDefaultAsync(cyberCase =>
                        cyberCase.Id == cyberCaseId &&
                        cyberCase.Path == CasePath.FormalReport &&
                        cyberCase.ReporterId == reporterId);
            if (cyberCase is null)
            {
                return false;
            }
            if (cyberCase.IsReporterIdentityDisclosed)
            {
                return true;
            }
            var reporter =
                await _dbContext.Users
                    .AsNoTracking()
                    .FirstOrDefaultAsync(user =>
                        user.Id == reporterId);
            if (reporter is null)
            {
                return false;
            }
            cyberCase.IsReporterIdentityDisclosed = true;
            cyberCase.DisclosedReporterName =
                string.IsNullOrWhiteSpace(reporter.FullName)
                    ? "غير محدد"
                    : reporter.FullName.Trim();
            cyberCase.DisclosedReporterEmail =
                reporter.Email;
            cyberCase.ReporterIdentityDisclosedAtUtc =
                DateTime.UtcNow;
            await _auditService.WriteAsync(new AuditLogRequest
            {
                Action = AuditAction.ReporterIdentityDisclosed,
                ActorUserId = reporterId,
                ActorEmail = reporter.Email,
                ActorRole = "USER",
                CyberCaseId = cyberCase.Id,
                EntityType = nameof(CyberCase),
                EntityId = cyberCase.Id,
                Description = "وافق المشتكي صراحة على كشف هويته للموظف المسؤول.",
                IsSuccessful = true
            });
            return true;
        });
    }

    // AuditService and NotificationService share this scoped DbContext.
    // Commit their saves together with the case operation; rollback on any failure.
    private async Task<T> ExecuteCaseTransactionAsync<T>(Func<Task<T>> operation)
    {
        await using var transaction =
            await _dbContext.Database.BeginTransactionAsync();
        try
        {
            T result = await operation();
            await _dbContext.SaveChangesAsync();
            await transaction.CommitAsync();
            return result;
        }
        catch
        {
            await transaction.RollbackAsync();
            _dbContext.ChangeTracker.Clear();
            throw;
        }
    }

}
