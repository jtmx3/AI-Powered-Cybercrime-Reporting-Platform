using System.ComponentModel.DataAnnotations;
using ACCP.Domain.Enums;

namespace ACCP.Domain.Entities;

public class CaseStatusHistory
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid CyberCaseId { get; set; }

    public CyberCase CyberCase { get; set; } = null!;

    public CaseStatus OldStatus { get; set; }

    public CaseStatus NewStatus { get; set; }

    public Guid ChangedByUserId { get; set; }

    public string ChangedByEmail { get; set; } = string.Empty;

    [StringLength(1000)]
    public string? Reason { get; set; }

    public DateTime ChangedAtUtc { get; set; } = DateTime.UtcNow;
}