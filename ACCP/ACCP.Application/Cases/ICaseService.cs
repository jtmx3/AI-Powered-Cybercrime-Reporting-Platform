using ACCP.Domain.Entities;
using ACCP.Domain.Enums;

namespace ACCP.Application.Cases;

public interface ICaseService
{
    Task<CyberCase> CreateForReporterAsync(
        CyberCase cyberCase,
        Guid reporterId);

    Task<List<CyberCase>> GetAllForReporterAsync(
        Guid reporterId);

    Task<CyberCase?> GetByIdForReporterAsync(
        Guid id,
        Guid reporterId);

    Task<List<CyberCase>> GetAllForOfficerAsync();

    Task<CyberCase?> GetByIdForOfficerAsync(
        Guid id,
        Guid officerId);

    Task<CyberCase?> GetByIdForAdminAsync(
        Guid id);

    Task<bool> UpdateStatusForOfficerAsync(
        Guid id,
        CaseStatus newStatus,
        Guid officerId,
        string officerEmail,
        string? reason = null);

    Task<bool> AssignToOfficerAsync(
        Guid id,
        Guid officerId,
        string officerEmail);

    Task<CaseNote?> AddInternalNoteForOfficerAsync(
        Guid cyberCaseId,
        string content,
        Guid officerId,
        string officerEmail);

    Task<CaseMessage?> SendMessageByReporterAsync(
        Guid cyberCaseId,
        string content,
        Guid reporterId,
        string reporterEmail);

    Task<CaseMessage?> SendMessageByOfficerAsync(
        Guid cyberCaseId,
        string content,
        Guid officerId,
        string officerEmail);

    Task<bool> DiscloseReporterIdentityAsync(
        Guid cyberCaseId,
        Guid reporterId);
}