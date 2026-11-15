using System.ComponentModel.DataAnnotations;

namespace ACCP.Domain.Entities;

public class CaseCollaborator
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid CyberCaseId { get; set; }

    public CyberCase CyberCase { get; set; } = null!;

    public Guid OfficerId { get; set; }

    [Required]
    [StringLength(256)]
    public string OfficerEmail { get; set; } = string.Empty;

    public Guid SourceRequestId { get; set; }

    public Guid AddedByAdminId { get; set; }

    [Required]
    [StringLength(256)]
    public string AddedByAdminEmail { get; set; } =
        string.Empty;

    public bool IsActive { get; set; } = true;

    public DateTime AddedAtUtc { get; set; } =
        DateTime.UtcNow;

    public Guid? RemovedByAdminId { get; set; }

    [StringLength(256)]
    public string? RemovedByAdminEmail { get; set; }

    [StringLength(1000)]
    public string? RemovalReason { get; set; }

    public DateTime? RemovedAtUtc { get; set; }

    [Timestamp]
    public byte[] RowVersion { get; set; } = [];
}
