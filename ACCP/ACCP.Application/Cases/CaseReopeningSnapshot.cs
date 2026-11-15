using ACCP.Domain.Enums;

namespace ACCP.Application.Cases;

// Administrative metadata only; no complaint text or reporter identity.
public sealed record CaseReopeningSnapshot(
    Guid CaseId,
    string CaseNumber,
    CaseStatus Status,
    Guid? OfficerId,
    DateTime? AssignedAtUtc,
    int HistoryCount);
