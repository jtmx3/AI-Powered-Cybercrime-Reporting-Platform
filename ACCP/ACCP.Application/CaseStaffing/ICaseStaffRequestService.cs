using ACCP.Domain.Entities;
using ACCP.Domain.Enums;

namespace ACCP.Application.CaseStaffing;

public interface ICaseStaffRequestService
{
    Task<CaseStaffRequest?> CreateForOfficerAsync(
        Guid cyberCaseId,
        CaseStaffRequestType requestType,
        string reason,
        Guid officerId,
        string officerEmail);

    Task<List<CaseStaffRequest>> GetForOfficerAsync(
        Guid officerId);

    Task<List<CaseStaffRequest>> GetForAdminAsync(
        CaseStaffRequestStatus? status = null);

    Task<CaseStaffRequest?> GetByIdForAdminAsync(
        Guid requestId);

    Task<bool> ApproveForAdminAsync(
        Guid requestId,
        Guid targetOfficerId,
        Guid adminId,
        string adminEmail,
        string? decisionNote);

    Task<bool> RejectForAdminAsync(
        Guid requestId,
        Guid adminId,
        string adminEmail,
        string decisionNote);

    Task<bool> CancelForOfficerAsync(
        Guid requestId,
        Guid officerId,
        string officerEmail);
}
