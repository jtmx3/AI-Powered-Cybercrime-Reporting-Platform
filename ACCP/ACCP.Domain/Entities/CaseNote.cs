using System.ComponentModel.DataAnnotations;

namespace ACCP.Domain.Entities;

public class CaseNote
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid CyberCaseId { get; set; }

    public CyberCase CyberCase { get; set; } = null!;

    [Required]
    [StringLength(2000)]
    public string Content { get; set; } = string.Empty;

    public Guid OfficerId { get; set; }

    [Required]
    [StringLength(256)]
    public string OfficerEmail { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; } =
        DateTime.UtcNow;
}