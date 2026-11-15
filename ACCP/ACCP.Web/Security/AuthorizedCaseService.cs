using System.ComponentModel.DataAnnotations;
using ACCP.Application.Auditing;
using ACCP.Application.Cases;
using ACCP.Application.Notifications;
using ACCP.Application.Security;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace ACCP.Web.Security;

/// <summary>
/// The web-facing case service. Identity and permissions come from the server,
/// never from the user IDs or email addresses supplied by a component.
/// Register as ICaseService only after the officer queue can claim a report
/// without first opening its private details.
/// Evidence endpoints and staffing services need their own authorization checks.
/// </summary>
public sealed class AuthorizedCaseService : ICaseService
{
    private readonly CaseAuthorizationService _authorization;
    private readonly IServiceScopeFactory _scopeFactory;

    public AuthorizedCaseService(
        CaseAuthorizationService authorization,
        IServiceScopeFactory scopeFactory)
    {
        _authorization = authorization;
        _scopeFactory = scopeFactory;
    }

    public async Task<CyberCase> CreateForReporterAsync(CyberCase cyberCase, Guid reporterId)
    {
        ArgumentNullException.ThrowIfNull(cyberCase);
        var actor = await ActorForAsync(reporterId, "USER");
        if (actor is null)
            throw new UnauthorizedAccessException("لا تملك صلاحية إنشاء هذا الطلب.");

        // Copy only intake fields. Ignore submitted IDs, assignment, status,
        // identity disclosure, files, messages, collaborators, and timestamps.
        var clean = new CyberCase
        {
            Title = cyberCase.Title?.Trim() ?? string.Empty,
            Description = cyberCase.Description?.Trim() ?? string.Empty,
            IncidentType = cyberCase.IncidentType?.Trim() ?? string.Empty,
            Path = cyberCase.Path,
            SeverityLevel = cyberCase.SeverityLevel,
            Status = CaseStatus.New
        };
        Validator.ValidateObject(clean, new ValidationContext(clean), validateAllProperties: true);
        if (!Enum.IsDefined(clean.Path) || !Enum.IsDefined(clean.SeverityLevel) ||
            clean.IncidentType is not ("Blackmail" or "Fraud" or "AccountHacking" or
                "IdentityTheft" or "Threat" or "Other"))
        {
            throw new ValidationException("بيانات الطلب غير صالحة.");
        }

        // The current intake flow is preserved here. AI risk and versioned
        // consent must be validated by the future server-owned chat workflow.
        return await WithCoreAsync((core, _) => core.CreateForReporterAsync(clean, actor.UserId));
    }

    public async Task<List<CyberCase>> GetAllForReporterAsync(Guid reporterId)
    {
        var actor = await ActorForAsync(reporterId, "USER");
        if (actor is null) return [];
        return await WithCoreAsync((_, db) => db.CyberCases.AsNoTracking()
            .Where(item => item.ReporterId == actor.UserId)
            .OrderByDescending(item => item.CreatedAtUtc)
            .Select(item => new CyberCase
            {
                Id = item.Id, CaseNumber = item.CaseNumber, Title = item.Title,
                IncidentType = item.IncidentType, SeverityLevel = item.SeverityLevel,
                Path = item.Path, Status = item.Status, CreatedAtUtc = item.CreatedAtUtc,
                AssignedOfficerId = item.AssignedOfficerId,
                AssignedOfficerEmail = item.AssignedOfficerEmail
            }).ToListAsync());
    }

    public async Task<CyberCase?> GetByIdForReporterAsync(Guid id, Guid reporterId)
    {
        if (!await AllowedAsync(id, reporterId, "USER", CasePermission.ReadDetails))
            return null;
        return await WithCoreAsync((core, _) => core.GetByIdForReporterAsync(id, reporterId));
    }

    public async Task<List<CyberCase>> GetAllForOfficerAsync()
    {
        var actor = await _authorization.GetCurrentActorAsync();
        if (actor is null || !actor.HasRole("OFFICER")) return [];
        return await WithCoreAsync(async (_, db) =>
        {
            var summaries = await db.CyberCases.AsNoTracking()
            .Where(item => item.Path == CasePath.FormalReport &&
                (item.AssignedOfficerId == actor.UserId ||
                 item.Collaborators.Any(collaborator => collaborator.IsActive &&
                     collaborator.OfficerId == actor.UserId) ||
                 (item.AssignedOfficerId == null &&
                     (item.Status == CaseStatus.New || item.Status == CaseStatus.UnderReview))))
            .OrderByDescending(item => item.CreatedAtUtc)
            .Select(item => new CyberCase
            {
                Id = item.Id, CaseNumber = item.CaseNumber,
                // An unclaimed report's user-written title may contain identity data.
                Title = item.AssignedOfficerId == actor.UserId ||
                    item.Collaborators.Any(collaborator => collaborator.IsActive &&
                        collaborator.OfficerId == actor.UserId)
                    ? item.Title : "بلاغ جديد بانتظار الاستلام",
                IncidentType = item.IncidentType, SeverityLevel = item.SeverityLevel,
                Path = item.Path, Status = item.Status, CreatedAtUtc = item.CreatedAtUtc,
                AssignedOfficerId = item.AssignedOfficerId,
                AssignedOfficerEmail = item.AssignedOfficerEmail
            }).ToListAsync();

            if (summaries.Count == 0) return summaries;
            // Fetch only identifiers for counts, with the case relationship
            // checked in SQL again. Never fetch filenames or private file metadata.
            var visibleEvidence = await db.EvidenceItems.AsNoTracking()
                .Where(evidence => evidence.CyberCase.Path == CasePath.FormalReport &&
                    (!evidence.IsRestricted || evidence.IsDisclosedToOfficer) &&
                    (evidence.CyberCase.AssignedOfficerId == actor.UserId ||
                     evidence.CyberCase.Collaborators.Any(collaborator => collaborator.IsActive &&
                         collaborator.OfficerId == actor.UserId)))
                .Select(evidence => new Evidence
                {
                    Id = evidence.Id, CyberCaseId = evidence.CyberCaseId
                }).ToListAsync();
            var collaborations = await db.CaseCollaborators.AsNoTracking()
                .Where(collaborator => collaborator.IsActive && collaborator.OfficerId == actor.UserId &&
                    collaborator.CyberCase.Path == CasePath.FormalReport)
                .Select(collaborator => new CaseCollaborator
                {
                    CyberCaseId = collaborator.CyberCaseId,
                    OfficerId = collaborator.OfficerId, IsActive = true
                }).ToListAsync();
            var byId = summaries.ToDictionary(item => item.Id);
            foreach (var evidence in visibleEvidence)
                if (byId.TryGetValue(evidence.CyberCaseId, out var item)) item.EvidenceItems.Add(evidence);
            foreach (var collaborator in collaborations)
                if (byId.TryGetValue(collaborator.CyberCaseId, out var item)) item.Collaborators.Add(collaborator);
            return summaries;
        });
    }

    public async Task<CyberCase?> GetByIdForOfficerAsync(Guid id, Guid officerId)
    {
        if (!await AllowedAsync(id, officerId, "OFFICER", CasePermission.ReadDetails))
            return null;
        var result = await WithCoreAsync((core, _) => core.GetByIdForOfficerAsync(id, officerId));
        if (result is not null) RemoveStaffIdentityMetadata(result);
        return result;
    }

    public async Task<CyberCase?> GetByIdForAdminAsync(Guid id)
    {
        // ADMIN grants account administration, not blanket access to complaints.
        // A separately granted OFFICER role uses the same case relationship rules.
        var actor = await _authorization.GetCurrentActorAsync();
        if (actor is null || !actor.HasRole("OFFICER")) return null;
        return await GetByIdForOfficerAsync(id, actor.UserId);
    }

    public async Task<bool> UpdateStatusForOfficerAsync(
        Guid id, CaseStatus newStatus, Guid officerId, string officerEmail,
        string? reason = null)
    {
        if (!Enum.IsDefined(newStatus) ||
            !await AllowedAsync(id, officerId, "OFFICER", CasePermission.ManageCase))
            return false;
        return await WithCoreAsync(async (core, db) =>
        {
            var email = await AccountEmailAsync(db, officerId);
            return email is not null && await core.UpdateStatusForOfficerAsync(id, newStatus, officerId, email, reason);
        });
    }

    public async Task<bool> AssignToOfficerAsync(Guid id, Guid officerId, string officerEmail)
    {
        if (!await AllowedAsync(id, officerId, "OFFICER", CasePermission.ClaimCase) &&
            !await AllowedAsync(id, officerId, "OFFICER", CasePermission.ManageCase))
            return false;
        // Existing owners may repeat a completed claim: the core service is idempotent.
        return await WithCoreAsync(async (core, db) =>
        {
            var email = await AccountEmailAsync(db, officerId);
            return email is not null && await core.AssignToOfficerAsync(id, officerId, email);
        });
    }

    public async Task<CaseNote?> AddInternalNoteForOfficerAsync(
        Guid cyberCaseId, string content, Guid officerId, string officerEmail)
    {
        if (!await AllowedAsync(cyberCaseId, officerId, "OFFICER", CasePermission.ParticipateInConversation))
            return null;
        return await WithCoreAsync<CaseNote?>(async (core, db) =>
        {
            var email = await AccountEmailAsync(db, officerId);
            if (email is null) return null;
            var note = await core.AddInternalNoteForOfficerAsync(cyberCaseId, content, officerId, email);
            if (note is not null) note.CyberCase = null!;
            return note;
        });
    }

    public async Task<CaseMessage?> SendMessageByReporterAsync(
        Guid cyberCaseId, string content, Guid reporterId, string reporterEmail)
    {
        if (!await AllowedAsync(cyberCaseId, reporterId, "USER", CasePermission.ParticipateInConversation))
            return null;
        return await WithCoreAsync<CaseMessage?>(async (core, db) =>
        {
            var email = await AccountEmailAsync(db, reporterId);
            if (email is null) return null;
            var message = await core.SendMessageByReporterAsync(cyberCaseId, content, reporterId, email);
            if (message is not null) message.CyberCase = null!;
            return message;
        });
    }

    public async Task<CaseMessage?> SendMessageByOfficerAsync(
        Guid cyberCaseId, string content, Guid officerId, string officerEmail)
    {
        if (!await AllowedAsync(cyberCaseId, officerId, "OFFICER", CasePermission.ParticipateInConversation))
            return null;
        return await WithCoreAsync<CaseMessage?>(async (core, db) =>
        {
            var email = await AccountEmailAsync(db, officerId);
            if (email is null) return null;
            var message = await core.SendMessageByOfficerAsync(cyberCaseId, content, officerId, email);
            if (message is not null) message.CyberCase = null!;
            return message;
        });
    }

    public async Task<bool> DiscloseReporterIdentityAsync(Guid cyberCaseId, Guid reporterId)
    {
        if (!await AllowedAsync(cyberCaseId, reporterId, "USER", CasePermission.ReadDetails))
            return false;
        return await WithCoreAsync((core, _) => core.DiscloseReporterIdentityAsync(cyberCaseId, reporterId));
    }

    private async Task<CaseAccessActor?> ActorForAsync(Guid userId, string role)
    {
        if (userId == Guid.Empty) return null;
        var actor = await _authorization.GetCurrentActorAsync();
        return actor is not null && actor.UserId == userId && actor.HasRole(role) ? actor : null;
    }

    private async Task<bool> AllowedAsync(Guid id, Guid userId, string role, CasePermission permission)
    {
        if (userId == Guid.Empty) return false;
        var decision = await _authorization.CheckAsync(id, permission);
        return decision.IsAllowed && decision.Actor is not null &&
            decision.Actor.UserId == userId && decision.Actor.HasRole(role);
    }

    private async Task<T> WithCoreAsync<T>(Func<CaseService, AccpDbContext, Task<T>> operation)
    {
        // One short-lived context per operation; audit and notifications share it
        // with the core service so existing transactional guarantees remain intact.
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var core = new CaseService(db,
            scope.ServiceProvider.GetRequiredService<IAuditService>(),
            scope.ServiceProvider.GetRequiredService<INotificationService>());
        return await operation(core, db);
    }

    private static async Task<string?> AccountEmailAsync(AccpDbContext db, Guid userId)
    {
        var email = await db.Users.AsNoTracking()
            .Where(user => user.Id == userId && user.IsActive)
            .Select(user => user.Email).FirstOrDefaultAsync();
        return !string.IsNullOrWhiteSpace(email) && email.Length <= 256 ? email.Trim() : null;
    }

    private static void RemoveStaffIdentityMetadata(CyberCase item)
    {
        item.ReporterId = null;
        if (!item.IsReporterIdentityDisclosed)
        {
            item.DisclosedReporterName = null;
            item.DisclosedReporterEmail = null;
            item.ReporterIdentityDisclosedAtUtc = null;
        }
        foreach (var message in item.Messages.Where(message => message.SenderType == MessageSenderType.User))
        {
            message.SenderId = Guid.Empty;
            if (!item.IsReporterIdentityDisclosed) message.SenderEmail = string.Empty;
        }
        foreach (var evidence in item.EvidenceItems)
        {
            evidence.DisclosedByReporterId = null;
            evidence.StorageKey = string.Empty;
            foreach (var revision in evidence.Revisions)
            {
                revision.ChangedByReporterId = Guid.Empty;
                revision.StorageKey = string.Empty;
            }
        }
    }
}