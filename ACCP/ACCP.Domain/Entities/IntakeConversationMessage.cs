using System.ComponentModel.DataAnnotations;

namespace ACCP.Domain.Entities;

public enum IntakeMessageRole
{
    Reporter = 0,
    Assistant = 1,
    Officer = 2,
    System = 3
}

public sealed class IntakeConversationMessage
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ConversationId { get; set; }

    public IntakeConversation Conversation { get; set; } = null!;

    // Assigned by the server. Timestamps alone do not determine order.
    public long SequenceNumber { get; set; }

    public IntakeMessageRole Role { get; set; }

    // Reporter/officer identity is assigned from the authenticated actor.
    // Assistant and system messages have no human author.
    public Guid? AuthorUserId { get; set; }

    [Required]
    [MaxLength(6000)]
    public string Content { get; set; } = string.Empty;

    // The service reuses this ID when retrying the same operation.
    // A database unique index will enforce deduplication per role.
    public Guid OperationId { get; set; }

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}