using System.ComponentModel.DataAnnotations;
using ACCP.Domain.Enums;

namespace ACCP.Domain.Entities;

public class AuditLog
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public AuditAction Action { get; set; }

    public Guid? ActorUserId { get; set; }

    [StringLength(256)]
    public string? ActorEmail { get; set; }

    [StringLength(50)]
    public string ActorRole { get; set; } = string.Empty;

    public Guid? CyberCaseId { get; set; }

    [Required]
    [StringLength(100)]
    public string EntityType { get; set; } = string.Empty;

    public Guid? EntityId { get; set; }

    [Required]
    [StringLength(1000)]
    public string Description { get; set; } = string.Empty;

    public bool IsSuccessful { get; set; } = true;

    [StringLength(500)]
    public string? FailureReason { get; set; }

    [StringLength(45)]
    public string? IpAddress { get; set; }

    [StringLength(500)]
    public string? UserAgent { get; set; }

    [StringLength(100)]
    public string? CorrelationId { get; set; }

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}