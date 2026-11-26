using ACCP.Application.Auditing;
using ACCP.Application.Security;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;

namespace ACCP.Infrastructure.Services;

public sealed class AuditService : IAuditService
{
    private const int MaximumResults = 1000;
    private const int MaximumSearchTermLength = 200;

    private readonly AccpDbContext _dbContext;
    private readonly IPiiMaskingService _piiMasking;

    public AuditService(
        AccpDbContext dbContext,
        IPiiMaskingService? piiMasking = null)
    {
        _dbContext = dbContext;
        _piiMasking = piiMasking ?? new PiiMaskingService();
    }

    public async Task<AuditLog> WriteAsync(
        AuditLogRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        string entityType = CleanRequired(
            request.EntityType,
            100,
            nameof(request.EntityType));

        string description = CleanRequired(
            _piiMasking.MaskSensitiveText(request.Description),
            1000,
            nameof(request.Description));

        string actorRole =
            CleanOptional(request.ActorRole, 50)
            ?? "SYSTEM";

        Guid? actorUserId =
            request.ActorUserId is { } userId &&
            userId != Guid.Empty
                ? userId
                : null;

        Guid? cyberCaseId =
            request.CyberCaseId is { } caseId &&
            caseId != Guid.Empty
                ? caseId
                : null;

        Guid? entityId =
            request.EntityId is { } targetId &&
            targetId != Guid.Empty
                ? targetId
                : null;

        var auditLog = new AuditLog
        {
            Action = request.Action,
            ActorUserId = actorUserId,
            ActorEmail = CleanOptional(
                request.ActorEmail,
                256),
            ActorRole = actorRole,
            CyberCaseId = cyberCaseId,
            EntityType = entityType,
            EntityId = entityId,
            Description = description,
            IsSuccessful = request.IsSuccessful,
            FailureReason = CleanOptional(
                request.FailureReason is null
                    ? null
                    : _piiMasking.MaskSensitiveText(request.FailureReason),
                500),
            IpAddress = CleanOptional(
                request.IpAddress,
                45),
            UserAgent = CleanOptional(
                request.UserAgent,
                500),
            CorrelationId = CleanOptional(
                request.CorrelationId,
                100),
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.AuditLogs.Add(auditLog);

        await _dbContext.SaveChangesAsync(
            cancellationToken);

        return auditLog;
    }

    public async Task<IReadOnlyList<AuditLog>>
        GetLatestAsync(
            int take = 200,
            CancellationToken cancellationToken = default)
    {
        int safeTake = NormalizeTake(take);

        return await _dbContext.AuditLogs
            .AsNoTracking()
            .OrderByDescending(auditLog =>
                auditLog.CreatedAtUtc)
            .Take(safeTake)
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<AuditLog>>
        GetForCaseAsync(
            Guid cyberCaseId,
            int take = 200,
            CancellationToken cancellationToken = default)
    {
        if (cyberCaseId == Guid.Empty)
        {
            return [];
        }

        int safeTake = NormalizeTake(take);

        return await _dbContext.AuditLogs
            .AsNoTracking()
            .Where(auditLog =>
                auditLog.CyberCaseId == cyberCaseId)
            .OrderByDescending(auditLog =>
                auditLog.CreatedAtUtc)
            .Take(safeTake)
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<AuditLog>> SearchAsync(
        string? searchTerm = null,
        AuditAction? action = null,
        bool? isSuccessful = null,
        int take = 500,
        CancellationToken cancellationToken = default)
    {
        int safeTake = NormalizeTake(take);

        IQueryable<AuditLog> query =
            _dbContext.AuditLogs
                .AsNoTracking();

        if (action.HasValue)
        {
            query = query.Where(auditLog =>
                auditLog.Action == action.Value);
        }

        if (isSuccessful.HasValue)
        {
            query = query.Where(auditLog =>
                auditLog.IsSuccessful ==
                    isSuccessful.Value);
        }

        string? cleanSearchTerm =
            CleanOptional(
                searchTerm,
                MaximumSearchTermLength);

        if (cleanSearchTerm is not null)
        {
            IQueryable<Guid> matchingCaseIds =
                _dbContext.CyberCases
                    .AsNoTracking()
                    .Where(cyberCase =>
                        cyberCase.CaseNumber.Contains(
                            cleanSearchTerm))
                    .Select(cyberCase => cyberCase.Id);

            if (Guid.TryParse(
                    cleanSearchTerm,
                    out Guid searchedId))
            {
                query = query.Where(auditLog =>
                    auditLog.ActorUserId == searchedId ||
                    auditLog.CyberCaseId == searchedId ||
                    auditLog.EntityId == searchedId ||
                    (auditLog.ActorEmail != null &&
                     auditLog.ActorEmail.Contains(
                         cleanSearchTerm)) ||
                    auditLog.ActorRole.Contains(
                        cleanSearchTerm) ||
                    auditLog.EntityType.Contains(
                        cleanSearchTerm) ||
                    auditLog.Description.Contains(
                        cleanSearchTerm) ||
                    (auditLog.FailureReason != null &&
                     auditLog.FailureReason.Contains(
                         cleanSearchTerm)) ||
                    (auditLog.CyberCaseId.HasValue &&
                     matchingCaseIds.Contains(
                         auditLog.CyberCaseId.Value)));
            }
            else
            {
                query = query.Where(auditLog =>
                    (auditLog.ActorEmail != null &&
                     auditLog.ActorEmail.Contains(
                         cleanSearchTerm)) ||
                    auditLog.ActorRole.Contains(
                        cleanSearchTerm) ||
                    auditLog.EntityType.Contains(
                        cleanSearchTerm) ||
                    auditLog.Description.Contains(
                        cleanSearchTerm) ||
                    (auditLog.FailureReason != null &&
                     auditLog.FailureReason.Contains(
                         cleanSearchTerm)) ||
                    (auditLog.CyberCaseId.HasValue &&
                     matchingCaseIds.Contains(
                         auditLog.CyberCaseId.Value)));
            }
        }

        return await query
            .OrderByDescending(auditLog =>
                auditLog.CreatedAtUtc)
            .Take(safeTake)
            .ToListAsync(cancellationToken);
    }

    private static int NormalizeTake(int take)
    {
        return Math.Clamp(
            take,
            1,
            MaximumResults);
    }

    private static string CleanRequired(
        string? value,
        int maximumLength,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(
                "القيمة المطلوبة فارغة.",
                parameterName);
        }

        string cleanValue = value.Trim();

        return cleanValue.Length <= maximumLength
            ? cleanValue
            : cleanValue[..maximumLength];
    }

    private static string? CleanOptional(
        string? value,
        int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string cleanValue = value.Trim();

        return cleanValue.Length <= maximumLength
            ? cleanValue
            : cleanValue[..maximumLength];
    }
}
