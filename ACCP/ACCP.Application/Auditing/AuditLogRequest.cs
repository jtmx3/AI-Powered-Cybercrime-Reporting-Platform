using ACCP.Domain.Enums;

namespace ACCP.Application.Auditing;

public sealed class AuditLogRequest
{
    public AuditAction Action { get; init; }

    public Guid? ActorUserId { get; init; }

    public string? ActorEmail { get; init; }

    public string ActorRole { get; init; } = "SYSTEM";

    public Guid? CyberCaseId { get; init; }

    public string EntityType { get; init; } = string.Empty;

    public Guid? EntityId { get; init; }

    public string Description { get; init; } = string.Empty;

    public bool IsSuccessful { get; init; } = true;

    public string? FailureReason { get; init; }

    public string? IpAddress { get; init; }

    public string? UserAgent { get; init; }

    public string? CorrelationId { get; init; }
}