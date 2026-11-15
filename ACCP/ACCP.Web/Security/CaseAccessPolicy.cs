using ACCP.Domain.Entities;
using ACCP.Domain.Enums;

namespace ACCP.Application.Security;

public enum CasePermission
{
    ReadQueueSummary,
    ReadDetails,
    ParticipateInConversation,
    ManageCase,
    ManageStaffing,
    ClaimCase,
    ReadReporterIdentity
}

/// <summary>
/// A snapshot built by server code from the authenticated identity and current account.
/// Never bind this object, its roles, or IsActive from browser input.
/// </summary>
public sealed class CaseAccessActor
{
    private readonly HashSet<string> _roles;

    public Guid UserId { get; }
    public bool IsAuthenticated { get; }
    public bool IsActive { get; }

    public CaseAccessActor(
        Guid userId,
        bool isAuthenticated,
        bool isActive,
        IEnumerable<string>? roles)
    {
        UserId = userId;
        IsAuthenticated = isAuthenticated;
        IsActive = isActive;
        _roles = roles is null
            ? new HashSet<string>(StringComparer.Ordinal)
            : new HashSet<string>(roles, StringComparer.Ordinal);
    }

    public bool HasRole(string role) => _roles.Contains(role);
}

/// <summary>
/// Case relationship rules. All inputs must be loaded and verified by the server.
/// The caller must load current collaborators before evaluating collaborator access.
/// MFA, evidence restrictions, consent to submit a report, and status transitions
/// are additional checks: permission here never overrides them.
/// </summary>
public static class CaseAccessPolicy
{
    private const string UserRole = "USER";
    private const string OfficerRole = "OFFICER";
    private const string SupervisorRole = "SUPERVISOR";

    public static bool IsAllowed(
        CaseAccessActor? actor,
        CyberCase? cyberCase,
        CasePermission permission,
        bool isWithinSupervisorScope = false)
    {
        if (actor is null || cyberCase is null ||
            !actor.IsAuthenticated || !actor.IsActive ||
            actor.UserId == Guid.Empty || cyberCase.Id == Guid.Empty ||
            !Enum.IsDefined(cyberCase.Path) || !Enum.IsDefined(permission))
        {
            return false;
        }

        bool isReporter = actor.HasRole(UserRole) &&
            cyberCase.ReporterId == actor.UserId;

        bool isFormalReport = cyberCase.Path == CasePath.FormalReport;
        bool isOfficer = actor.HasRole(OfficerRole);
        bool isResponsibleOfficer = isFormalReport && isOfficer &&
            cyberCase.AssignedOfficerId == actor.UserId;

        bool isCollaborator = isFormalReport && isOfficer &&
            cyberCase.Collaborators.Any(collaborator =>
                collaborator.CyberCaseId == cyberCase.Id &&
                collaborator.OfficerId == actor.UserId &&
                collaborator.IsActive);

        // Scope is established by the server from the supervisor's team/assignment.
        // The default is false until that scope has been verified.
        bool isScopedSupervisor = isFormalReport &&
            actor.HasRole(SupervisorRole) && isWithinSupervisorScope;

        bool isStaffParticipant = isResponsibleOfficer ||
            isCollaborator || isScopedSupervisor;

        bool isAvailableForClaim = isFormalReport &&
            !cyberCase.AssignedOfficerId.HasValue &&
            cyberCase.Status is CaseStatus.New or CaseStatus.UnderReview;

        // ADMIN alone does not grant access to case contents or the reporter's identity.
        // Another explicitly granted role is evaluated using its own relationship rules.
        return permission switch
        {
            CasePermission.ReadQueueSummary =>
                isFormalReport && (isStaffParticipant || (isOfficer && isAvailableForClaim)),

            CasePermission.ReadDetails =>
                isReporter || isStaffParticipant,

            CasePermission.ParticipateInConversation =>
                isReporter || isStaffParticipant,

            CasePermission.ManageCase =>
                isResponsibleOfficer || isScopedSupervisor,

            CasePermission.ManageStaffing =>
                isResponsibleOfficer || isScopedSupervisor,

            CasePermission.ClaimCase =>
                isOfficer && isAvailableForClaim,

            CasePermission.ReadReporterIdentity =>
                isReporter || (isStaffParticipant && cyberCase.IsReporterIdentityDisclosed),

            _ => false
        };
    }
}