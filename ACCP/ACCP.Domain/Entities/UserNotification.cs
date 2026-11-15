using System.ComponentModel.DataAnnotations;
using ACCP.Domain.Enums;

namespace ACCP.Domain.Entities;

public class UserNotification
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid RecipientUserId { get; set; }

    public Guid? CyberCaseId { get; set; }

    public CyberCase? CyberCase { get; set; }

    public NotificationType Type { get; set; }

    [Required]
    [StringLength(200)]
    public string Title { get; set; } = string.Empty;

    [Required]
    [StringLength(1000)]
    public string Message { get; set; } = string.Empty;

    public bool IsRead { get; set; }

    public DateTime CreatedAtUtc { get; set; } =
        DateTime.UtcNow;

    public DateTime? ReadAtUtc { get; set; }
}