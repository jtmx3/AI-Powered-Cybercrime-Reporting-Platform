using System.ComponentModel.DataAnnotations;
using ACCP.Domain.Enums;

namespace ACCP.Domain.Entities;

public class CaseStaffRequest
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid CyberCaseId { get; set; }

    public CyberCase CyberCase { get; set; } = null!;

    public Guid RequestedByOfficerId { get; set; }

    [Required]
    [StringLength(256)]
    public string RequestedByOfficerEmail { get; set; } =
        string.Empty;

    public CaseStaffRequestType RequestType { get; set; }

    [Required]
    [StringLength(1000, MinimumLength = 10)]
    public string Reason { get; set; } = string.Empty;

    public CaseStaffRequestStatus Status { get; set; } =
        CaseStaffRequestStatus.Pending;

    public Guid? TargetOfficerId { get; set; }

    [StringLength(256)]
    public string? TargetOfficerEmail { get; set; }

    public Guid? ReviewedByAdminId { get; set; }

    [StringLength(256)]
    public string? ReviewedByAdminEmail { get; set; }

    [StringLength(1000)]
    public string? DecisionNote { get; set; }

    public DateTime CreatedAtUtc { get; set; } =
        DateTime.UtcNow;

    public DateTime? ReviewedAtUtc { get; set; }

    [Timestamp]
    public byte[] RowVersion { get; set; } = [];
}
