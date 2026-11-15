using ACCP.Domain.Entities;
using ACCP.Domain.Enums;

namespace ACCP.Application.Auditing;

public interface IAuditService
{
    Task<AuditLog> WriteAsync(
        AuditLogRequest request,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AuditLog>> GetLatestAsync(
        int take = 200,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AuditLog>> GetForCaseAsync(
        Guid cyberCaseId,
        int take = 200,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AuditLog>> SearchAsync(
        string? searchTerm = null,
        AuditAction? action = null,
        bool? isSuccessful = null,
        int take = 500,
        CancellationToken cancellationToken = default);
}
