using System.Data;
using ACCP.Application.Auditing;
using ACCP.Application.CaseStaffing;
using ACCP.Application.Notifications;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace ACCP.Infrastructure.Services;

public sealed class CaseStaffRequestService : ICaseStaffRequestService
{
    private readonly AccpDbContext _dbContext;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly INotificationService _notificationService;
    private readonly IAuditService _auditService;

    public CaseStaffRequestService(
        AccpDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        INotificationService notificationService,
        IAuditService auditService)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _notificationService = notificationService;
        _auditService = auditService;
    }

    public async Task<CaseStaffRequest?> CreateForOfficerAsync(
        Guid cyberCaseId,
        CaseStaffRequestType requestType,
        string reason,
        Guid officerId,
        string officerEmail)
    {
        var cleanReason = reason?.Trim() ?? string.Empty;

        if (cyberCaseId == Guid.Empty ||
            officerId == Guid.Empty ||
            !IsValidRequestType(requestType) ||
            cleanReason.Length is < 10 or > 1000)
        {
            return null;
        }

        await using var transaction =
            await _dbContext.Database.BeginTransactionAsync(
                IsolationLevel.Serializable);

        try
        {
            var officer = await GetValidatedUserAsync(
                officerId, officerEmail, IdentityRoles.Officer);

            if (officer is null)
                return null;

            var cyberCase = await _dbContext.CyberCases
                .FirstOrDefaultAsync(item =>
                    item.Id == cyberCaseId &&
                    item.Path == CasePath.FormalReport);

            if (cyberCase is null ||
                cyberCase.AssignedOfficerId != officerId ||
                !IsOpen(cyberCase.Status))
            {
                return null;
            }

            var hasPending = await _dbContext.CaseStaffRequests
                .AnyAsync(item =>
                    item.CyberCaseId == cyberCaseId &&
                    item.Status == CaseStaffRequestStatus.Pending);

            if (hasPending)
                return null;

            var request = new CaseStaffRequest
            {
                CyberCaseId = cyberCase.Id,
                RequestedByOfficerId = officer.Id,
                RequestedByOfficerEmail = officer.Email!.Trim(),
                RequestType = requestType,
                Reason = cleanReason,
                Status = CaseStaffRequestStatus.Pending,
                CreatedAtUtc = DateTime.UtcNow
            };

            _dbContext.CaseStaffRequests.Add(request);
            await _dbContext.SaveChangesAsync();

            await NotifyAdminsAsync(
                cyberCase.Id,
                NotificationType.CaseStaffRequestCreated,
                "طلب موظف جديد",
                $"تم إرسال طلب {GetRequestTypeText(requestType)} " +
                $"للقضية {cyberCase.CaseNumber}.");

            await _auditService.WriteAsync(new AuditLogRequest
            {
                Action = AuditAction.CaseStaffRequestCreated,
                ActorUserId = officer.Id,
                ActorEmail = officer.Email,
                ActorRole = IdentityRoles.Officer,
                CyberCaseId = cyberCase.Id,
                EntityType = nameof(CaseStaffRequest),
                EntityId = request.Id,
                Description =
                    $"أنشأ الموظف طلب {GetRequestTypeText(requestType)} " +
                    $"للقضية {cyberCase.CaseNumber}."
            });

            await transaction.CommitAsync();
            return request;
        }
        catch
        {
            await transaction.RollbackAsync();
            _dbContext.ChangeTracker.Clear();
            throw;
        }
    }

    public async Task<List<CaseStaffRequest>> GetForOfficerAsync(
        Guid officerId)
    {
        if (officerId == Guid.Empty)
            return [];

        return await _dbContext.CaseStaffRequests
            .AsNoTracking()
            .Include(item => item.CyberCase)
            .Where(item =>
                item.CyberCase.Path == CasePath.FormalReport &&
                item.RequestedByOfficerId == officerId)
            .OrderByDescending(item => item.CreatedAtUtc)
            .ThenBy(item => item.Id)
            .ToListAsync();
    }

    public async Task<List<CaseStaffRequest>> GetForAdminAsync(
        CaseStaffRequestStatus? status = null)
    {
        if (status.HasValue && !Enum.IsDefined(status.Value))
            throw new ArgumentOutOfRangeException(nameof(status));

        var query = AdminReadQuery();

        if (status.HasValue)
            query = query.Where(item => item.Status == status.Value);

        return await query
            .OrderByDescending(item => item.CreatedAtUtc)
            .ThenBy(item => item.Id)
            .ToListAsync();
    }

    public async Task<CaseStaffRequest?> GetByIdForAdminAsync(
        Guid requestId)
    {
        if (requestId == Guid.Empty)
            return null;

        return await AdminReadQuery()
            .FirstOrDefaultAsync(item => item.Id == requestId);
    }

    // بيانات إدارية فقط؛ لا نحمل عنوان القضية أو وصفها أو هوية المشتكي.
    private IQueryable<CaseStaffRequest> AdminReadQuery() =>
        _dbContext.CaseStaffRequests
            .AsNoTracking()
            .Where(item =>
                item.CyberCase.Path == CasePath.FormalReport)
            .Select(item => new CaseStaffRequest
            {
                Id = item.Id,
                CyberCaseId = item.CyberCaseId,
                CyberCase = new CyberCase
                {
                    Id = item.CyberCaseId,
                    CaseNumber = item.CyberCase.CaseNumber,
                    AssignedOfficerId =
                        item.CyberCase.AssignedOfficerId,
                    Path = item.CyberCase.Path
                },
                RequestedByOfficerId = item.RequestedByOfficerId,
                RequestedByOfficerEmail = item.RequestedByOfficerEmail,
                RequestType = item.RequestType,
                Reason = item.Reason,
                Status = item.Status,
                TargetOfficerId = item.TargetOfficerId,
                TargetOfficerEmail = item.TargetOfficerEmail,
                ReviewedByAdminId = item.ReviewedByAdminId,
                ReviewedByAdminEmail = item.ReviewedByAdminEmail,
                DecisionNote = item.DecisionNote,
                CreatedAtUtc = item.CreatedAtUtc,
                ReviewedAtUtc = item.ReviewedAtUtc,
                RowVersion = item.RowVersion
            });

    public async Task<bool> ApproveForAdminAsync(
        Guid requestId,
        Guid targetOfficerId,
        Guid adminId,
        string adminEmail,
        string? decisionNote)
    {
        if (requestId == Guid.Empty ||
            targetOfficerId == Guid.Empty ||
            adminId == Guid.Empty)
        {
            return false;
        }

        var cleanNote = CleanOptionalText(decisionNote, 1000);

        if (!string.IsNullOrWhiteSpace(decisionNote) &&
            cleanNote is null)
        {
            return false;
        }

        await using var transaction =
            await _dbContext.Database.BeginTransactionAsync(
                IsolationLevel.Serializable);

        try
        {
            // يعاد فحص الحسابات والأدوار داخل معاملة القرار.
            var admin = await GetValidatedUserAsync(
                adminId, adminEmail, IdentityRoles.Admin);

            var target = await GetEligibleTargetAsync(targetOfficerId);

            if (admin is null || target is null)
                return false;

            var request = await _dbContext.CaseStaffRequests
                .Include(item => item.CyberCase)
                .FirstOrDefaultAsync(item =>
                    item.Id == requestId &&
                    item.Status == CaseStaffRequestStatus.Pending &&
                    item.CyberCase.Path == CasePath.FormalReport);

            if (request is null ||
                !IsValidRequestType(request.RequestType) ||
                !IsOpen(request.CyberCase.Status) ||
                request.CyberCase.AssignedOfficerId !=
                    request.RequestedByOfficerId ||
                target.Id == request.RequestedByOfficerId ||
                target.Id == request.CyberCase.AssignedOfficerId)
            {
                return false;
            }

            // لا نغيّر الطلب إذا كان الموظف مشاركًا فعّالًا بالفعل.
            if (request.RequestType == CaseStaffRequestType.AddCollaborator &&
                await _dbContext.CaseCollaborators.AnyAsync(item =>
                    item.CyberCaseId == request.CyberCaseId &&
                    item.OfficerId == target.Id &&
                    item.IsActive))
            {
                return false;
            }

            var now = DateTime.UtcNow;

            request.Status = CaseStaffRequestStatus.Approved;
            request.TargetOfficerId = target.Id;
            request.TargetOfficerEmail = target.Email!.Trim();
            request.ReviewedByAdminId = admin.Id;
            request.ReviewedByAdminEmail = admin.Email!.Trim();
            request.DecisionNote = cleanNote;
            request.ReviewedAtUtc = now;

            if (request.RequestType ==
                CaseStaffRequestType.TransferAssignment)
            {
                await ApplyTransferAsync(request, target, admin, now);
            }
            else
            {
                await ApplyCollaborationAsync(request, target, admin, now);
            }

            await _dbContext.SaveChangesAsync();

            await _notificationService.CreateAsync(
                request.RequestedByOfficerId,
                request.CyberCaseId,
                NotificationType.CaseStaffRequestApproved,
                "تمت الموافقة على طلبك",
                $"وافق المدير على طلب {GetRequestTypeText(request.RequestType)} " +
                $"للقضية {request.CyberCase.CaseNumber}.");

            await _auditService.WriteAsync(new AuditLogRequest
            {
                Action = AuditAction.CaseStaffRequestApproved,
                ActorUserId = admin.Id,
                ActorEmail = admin.Email,
                ActorRole = IdentityRoles.Admin,
                CyberCaseId = request.CyberCaseId,
                EntityType = nameof(CaseStaffRequest),
                EntityId = request.Id,
                Description =
                    $"وافق المدير على طلب {GetRequestTypeText(request.RequestType)} " +
                    $"للقضية {request.CyberCase.CaseNumber}، " +
                    $"وحدد الموظف {target.Email}."
            });

            await transaction.CommitAsync();
            return true;
        }
        catch (DbUpdateException)
        {
            await transaction.RollbackAsync();
            _dbContext.ChangeTracker.Clear();
            return false;
        }
        catch
        {
            await transaction.RollbackAsync();
            _dbContext.ChangeTracker.Clear();
            throw;
        }
    }

    public async Task<bool> RejectForAdminAsync(
        Guid requestId,
        Guid adminId,
        string adminEmail,
        string decisionNote)
    {
        var note = decisionNote?.Trim() ?? string.Empty;

        if (requestId == Guid.Empty ||
            adminId == Guid.Empty ||
            note.Length is < 5 or > 1000)
        {
            return false;
        }

        await using var transaction =
            await _dbContext.Database.BeginTransactionAsync(
                IsolationLevel.Serializable);

        try
        {
            var admin = await GetValidatedUserAsync(
                adminId, adminEmail, IdentityRoles.Admin);

            if (admin is null)
                return false;

            var request = await _dbContext.CaseStaffRequests
                .Include(item => item.CyberCase)
                .FirstOrDefaultAsync(item =>
                    item.Id == requestId &&
                    item.Status == CaseStaffRequestStatus.Pending &&
                    item.CyberCase.Path == CasePath.FormalReport);

            if (request is null)
                return false;

            request.Status = CaseStaffRequestStatus.Rejected;
            request.ReviewedByAdminId = admin.Id;
            request.ReviewedByAdminEmail = admin.Email!.Trim();
            request.DecisionNote = note;
            request.ReviewedAtUtc = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            // السبب الكامل محفوظ في الطلب؛ نص الإشعار يبقى ضمن حدوده.
            await _notificationService.CreateAsync(
                request.RequestedByOfficerId,
                request.CyberCaseId,
                NotificationType.CaseStaffRequestRejected,
                "تم رفض طلبك",
                $"رفض المدير طلب {GetRequestTypeText(request.RequestType)} " +
                $"للقضية {request.CyberCase.CaseNumber}. " +
                "يمكنك مراجعة سبب الرفض في سجل طلبات القضية.");

            await _auditService.WriteAsync(new AuditLogRequest
            {
                Action = AuditAction.CaseStaffRequestRejected,
                ActorUserId = admin.Id,
                ActorEmail = admin.Email,
                ActorRole = IdentityRoles.Admin,
                CyberCaseId = request.CyberCaseId,
                EntityType = nameof(CaseStaffRequest),
                EntityId = request.Id,
                Description =
                    $"رفض المدير طلب {GetRequestTypeText(request.RequestType)} " +
                    $"للقضية {request.CyberCase.CaseNumber}."
            });

            await transaction.CommitAsync();
            return true;
        }
        catch (DbUpdateException)
        {
            await transaction.RollbackAsync();
            _dbContext.ChangeTracker.Clear();
            return false;
        }
        catch
        {
            await transaction.RollbackAsync();
            _dbContext.ChangeTracker.Clear();
            throw;
        }
    }

    public async Task<bool> CancelForOfficerAsync(
        Guid requestId,
        Guid officerId,
        string officerEmail)
    {
        if (requestId == Guid.Empty || officerId == Guid.Empty)
            return false;

        await using var transaction =
            await _dbContext.Database.BeginTransactionAsync(
                IsolationLevel.Serializable);

        try
        {
            var officer = await GetValidatedUserAsync(
                officerId, officerEmail, IdentityRoles.Officer);

            if (officer is null)
                return false;

            var request = await _dbContext.CaseStaffRequests
                .Include(item => item.CyberCase)
                .FirstOrDefaultAsync(item =>
                    item.Id == requestId &&
                    item.RequestedByOfficerId == officerId &&
                    item.Status == CaseStaffRequestStatus.Pending &&
                    item.CyberCase.Path == CasePath.FormalReport);

            if (request is null)
                return false;

            request.Status = CaseStaffRequestStatus.Cancelled;
            request.DecisionNote = "ألغى الموظف الطلب قبل مراجعته.";
            request.ReviewedAtUtc = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            await NotifyAdminsAsync(
                request.CyberCaseId,
                NotificationType.CaseStaffRequestCancelled,
                "أُلغي طلب موظف",
                $"ألغى الموظف طلب {GetRequestTypeText(request.RequestType)} " +
                $"للقضية {request.CyberCase.CaseNumber}.");

            await _auditService.WriteAsync(new AuditLogRequest
            {
                Action = AuditAction.CaseStaffRequestCancelled,
                ActorUserId = officer.Id,
                ActorEmail = officer.Email,
                ActorRole = IdentityRoles.Officer,
                CyberCaseId = request.CyberCaseId,
                EntityType = nameof(CaseStaffRequest),
                EntityId = request.Id,
                Description =
                    $"ألغى الموظف طلب {GetRequestTypeText(request.RequestType)} " +
                    $"للقضية {request.CyberCase.CaseNumber}."
            });

            await transaction.CommitAsync();
            return true;
        }
        catch (DbUpdateException)
        {
            await transaction.RollbackAsync();
            _dbContext.ChangeTracker.Clear();
            return false;
        }
        catch
        {
            await transaction.RollbackAsync();
            _dbContext.ChangeTracker.Clear();
            throw;
        }
    }

    private async Task ApplyTransferAsync(
        CaseStaffRequest request,
        ApplicationUser target,
        ApplicationUser admin,
        DateTime now)
    {
        var previousOfficerId = request.CyberCase.AssignedOfficerId;

        // تنظيف مشاركة المسؤول السابق ومشاركة المسؤول الجديد فقط.
        // تبقى مشاركات الموظفين الآخرين دون تغيير.
        var collaborations = await _dbContext.CaseCollaborators
            .Where(item =>
                item.CyberCaseId == request.CyberCaseId &&
                item.IsActive &&
                (item.OfficerId == previousOfficerId ||
                 item.OfficerId == target.Id))
            .ToListAsync();

        foreach (var collaboration in collaborations)
        {
            collaboration.IsActive = false;
            collaboration.RemovedByAdminId = admin.Id;
            collaboration.RemovedByAdminEmail = admin.Email!.Trim();
            collaboration.RemovedAtUtc = now;
            collaboration.RemovalReason =
                collaboration.OfficerId == target.Id
                    ? "أصبح الموظف مسؤولًا عن القضية بعد الموافقة على النقل."
                    : "انتهت مسؤولية الموظف عن القضية بعد الموافقة على النقل.";
        }

        request.CyberCase.AssignedOfficerId = target.Id;
        request.CyberCase.AssignedOfficerEmail = target.Email!.Trim();
        request.CyberCase.AssignedAtUtc = now;

        // إلغاء أي طلبات أخرى معلقة مرتبطة بالإسناد السابق.
        var otherPending = await _dbContext.CaseStaffRequests
            .Where(item =>
                item.CyberCaseId == request.CyberCaseId &&
                item.Id != request.Id &&
                item.Status == CaseStaffRequestStatus.Pending)
            .ToListAsync();

        foreach (var pending in otherPending)
        {
            pending.Status = CaseStaffRequestStatus.Cancelled;
            pending.ReviewedByAdminId = admin.Id;
            pending.ReviewedByAdminEmail = admin.Email!.Trim();
            pending.ReviewedAtUtc = now;
            pending.DecisionNote =
                "أُلغي الطلب بسبب تغيير المسؤول عن القضية.";

            await _notificationService.CreateAsync(
                pending.RequestedByOfficerId,
                request.CyberCaseId,
                NotificationType.CaseStaffRequestCancelled,
                "أُلغي طلب سابق",
                $"أُلغي طلب سابق للقضية {request.CyberCase.CaseNumber} " +
                "بسبب تغيير المسؤول عنها.");

            await _auditService.WriteAsync(new AuditLogRequest
            {
                Action = AuditAction.CaseStaffRequestCancelled,
                ActorUserId = admin.Id,
                ActorEmail = admin.Email,
                ActorRole = IdentityRoles.Admin,
                CyberCaseId = request.CyberCaseId,
                EntityType = nameof(CaseStaffRequest),
                EntityId = pending.Id,
                Description =
                    "أُلغي طلب معلّق بسبب تغيير المسؤول عن القضية."
            });
        }

        await _notificationService.CreateAsync(
            target.Id,
            request.CyberCaseId,
            NotificationType.CaseAssignmentTransferred,
            "تم تحويل قضية إليك",
            $"تم تعيينك مسؤولًا عن القضية {request.CyberCase.CaseNumber}.");

        await _auditService.WriteAsync(new AuditLogRequest
        {
            Action = AuditAction.CaseAssignmentTransferred,
            ActorUserId = admin.Id,
            ActorEmail = admin.Email,
            ActorRole = IdentityRoles.Admin,
            CyberCaseId = request.CyberCaseId,
            EntityType = nameof(CyberCase),
            EntityId = request.CyberCaseId,
            Description =
                $"حوّل المدير مسؤولية القضية من الموظف " +
                $"{previousOfficerId} إلى {target.Email}."
        });
    }

    private async Task ApplyCollaborationAsync(
        CaseStaffRequest request,
        ApplicationUser target,
        ApplicationUser admin,
        DateTime now)
    {
        var collaborator = await _dbContext.CaseCollaborators
            .FirstOrDefaultAsync(item =>
                item.CyberCaseId == request.CyberCaseId &&
                item.OfficerId == target.Id);

        if (collaborator is null)
        {
            collaborator = new CaseCollaborator
            {
                CyberCaseId = request.CyberCaseId,
                OfficerId = target.Id
            };

            _dbContext.CaseCollaborators.Add(collaborator);
        }

        collaborator.OfficerEmail = target.Email!.Trim();
        collaborator.SourceRequestId = request.Id;
        collaborator.AddedByAdminId = admin.Id;
        collaborator.AddedByAdminEmail = admin.Email!.Trim();
        collaborator.IsActive = true;
        collaborator.AddedAtUtc = now;
        collaborator.RemovedByAdminId = null;
        collaborator.RemovedByAdminEmail = null;
        collaborator.RemovalReason = null;
        collaborator.RemovedAtUtc = null;

        await _notificationService.CreateAsync(
            target.Id,
            request.CyberCaseId,
            NotificationType.CaseCollaborationAdded,
            "تمت إضافتك إلى قضية",
            $"أضافك المدير كموظف مشارك في القضية " +
            $"{request.CyberCase.CaseNumber}.");

        await _auditService.WriteAsync(new AuditLogRequest
        {
            Action = AuditAction.CaseCollaboratorAdded,
            ActorUserId = admin.Id,
            ActorEmail = admin.Email,
            ActorRole = IdentityRoles.Admin,
            CyberCaseId = request.CyberCaseId,
            EntityType = nameof(CaseCollaborator),
            EntityId = collaborator.Id,
            Description =
                $"أضاف المدير الموظف {target.Email} كمشارك " +
                $"في القضية {request.CyberCase.CaseNumber}."
        });
    }

    private async Task<ApplicationUser?> GetEligibleTargetAsync(
        Guid userId)
    {
        var user = await GetActiveUserInRoleAsync(
            userId, IdentityRoles.Officer);

        if (user is null)
            return null;

        // لا يُستخدم حساب يحمل دور مدير كموظف بديل أو مشارك.
        if (await HasRoleAsync(user.Id, IdentityRoles.Admin))
            return null;

        return user;
    }

    private async Task<ApplicationUser?> GetValidatedUserAsync(
        Guid userId,
        string email,
        string requiredRole)
    {
        if (string.IsNullOrWhiteSpace(email))
            return null;

        var user = await GetActiveUserInRoleAsync(userId, requiredRole);

        if (user is null ||
            !string.Equals(
                user.Email!.Trim(),
                email.Trim(),
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return user;
    }

    private async Task<ApplicationUser?> GetActiveUserInRoleAsync(
        Guid userId,
        string requiredRole)
    {
        if (userId == Guid.Empty)
            return null;

        // قراءة جديدة من قاعدة البيانات داخل معاملة العملية.
        var user = await _dbContext.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(item => item.Id == userId);

        if (user is null ||
            !user.IsActive ||
            string.IsNullOrWhiteSpace(user.Email) ||
            (user.LockoutEnabled &&
             user.LockoutEnd is { } lockout &&
             lockout > DateTimeOffset.UtcNow) ||
            !await HasRoleAsync(user.Id, requiredRole))
        {
            return null;
        }

        return user;
    }

    private Task<bool> HasRoleAsync(Guid userId, string roleName) =>
        _dbContext.UserRoles
            .Join(
                _dbContext.Roles,
                membership => membership.RoleId,
                role => role.Id,
                (membership, role) => new
                {
                    membership.UserId,
                    RoleName = role.Name
                })
            .AnyAsync(item =>
                item.UserId == userId &&
                item.RoleName == roleName);

    private async Task NotifyAdminsAsync(
        Guid caseId,
        NotificationType type,
        string title,
        string message)
    {
        var admins = await _userManager.GetUsersInRoleAsync(
            IdentityRoles.Admin);

        foreach (var admin in admins)
        {
            if (!admin.IsActive)
                continue;

            await _notificationService.CreateAsync(
                admin.Id, caseId, type, title, message);
        }
    }

    private static bool IsOpen(CaseStatus status) =>
        status is CaseStatus.New or
            CaseStatus.UnderReview or
            CaseStatus.Assigned or
            CaseStatus.InProgress;

    private static bool IsValidRequestType(
        CaseStaffRequestType type) =>
        type is CaseStaffRequestType.TransferAssignment or
            CaseStaffRequestType.AddCollaborator;

    private static string? CleanOptionalText(
        string? value,
        int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var clean = value.Trim();
        return clean.Length <= maximumLength ? clean : null;
    }

    private static string GetRequestTypeText(
        CaseStaffRequestType type) =>
        type switch
        {
            CaseStaffRequestType.TransferAssignment =>
                "نقل مسؤولية القضية",
            CaseStaffRequestType.AddCollaborator =>
                "إضافة موظف مشارك",
            _ => "غير معروف"
        };
}