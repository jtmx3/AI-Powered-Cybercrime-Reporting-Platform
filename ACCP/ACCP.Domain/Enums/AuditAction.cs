namespace ACCP.Domain.Enums;

public enum AuditAction
{
    UserLoggedIn = 1,
    UserLoginFailed = 2,
    UserLoggedOut = 3,

    CaseCreated = 10,
    CaseAssigned = 11,
    CaseStatusChanged = 12,
    InternalNoteAdded = 13,
    CaseMessageSent = 14,
    CaseStaffRequestCreated = 15,
    CaseStaffRequestApproved = 16,
    CaseStaffRequestRejected = 17,
    CaseStaffRequestCancelled = 18,
    CaseCollaboratorAdded = 19,

    ReporterIdentityDisclosed = 20,
    CaseAssignmentTransferred = 21,
    CaseCollaboratorRemoved = 22,

    EvidenceUploaded = 30,
    EvidenceDisclosureGranted = 31,
    EvidenceRevisionUploaded = 32,
    EvidenceViewed = 33,

    AccessDenied = 40,

    AccountCreated = 50,
    UserRoleChanged = 51,
    AccountActivated = 52,
    AccountDeactivated = 53,
    AccountPasswordReset = 54,
    AccountEmailChanged = 55,

    TwoFactorEnabled = 60,
    TwoFactorRecoveryCodesRegenerated = 61,
    TwoFactorDisabled = 62
}