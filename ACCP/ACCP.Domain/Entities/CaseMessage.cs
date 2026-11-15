using System.ComponentModel.DataAnnotations;
using ACCP.Domain.Enums;

namespace ACCP.Domain.Entities;

public class CaseMessage
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid CyberCaseId { get; set; }

    public CyberCase CyberCase { get; set; } = null!;

    [Required]
    [StringLength(4000)]
    public string Content { get; set; } = string.Empty;

    public Guid SenderId { get; set; }

    [Required]
    [StringLength(256)]
    public string SenderEmail { get; set; } = string.Empty;

    public MessageSenderType SenderType { get; set; }

    public DateTime CreatedAtUtc { get; set; } =
        DateTime.UtcNow;
}