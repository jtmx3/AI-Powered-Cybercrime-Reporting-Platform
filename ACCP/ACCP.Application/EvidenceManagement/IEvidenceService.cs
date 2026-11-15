using ACCP.Domain.Entities;

namespace ACCP.Application.EvidenceManagement;

public interface IEvidenceService
{
    Task<Evidence> UploadAsync(
        EvidenceUploadRequest request,
        Guid reporterId);

    Task<List<Evidence>> GetByCaseIdAsync(
        Guid cyberCaseId,
        Guid reporterId);

    Task<bool> DiscloseToOfficerAsync(
        Guid evidenceId,
        Guid reporterId);

    Task<EvidenceRevision> UploadRevisionAsync(
        EvidenceRevisionUploadRequest request,
        Guid reporterId);
}