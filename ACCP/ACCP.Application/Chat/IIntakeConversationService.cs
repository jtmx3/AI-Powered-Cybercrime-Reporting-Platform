using ACCP.Domain.Entities;

namespace ACCP.Application.Chat;

/// <summary>
/// Reporter-facing persistence operations.
/// The implementation must resolve and validate the current authenticated
/// reporter on every call. Caller-supplied IDs never establish ownership.
/// </summary>
public interface IIntakeConversationService
{
    // The caller retains conversationId across retries.
    // An existing ID is returned only if owned by the current reporter.
    Task<IntakeConversationInfo> CreateAsync(
        Guid conversationId,
        CancellationToken cancellationToken = default);

    // Unknown and inaccessible conversations both return null.
    Task<IntakeConversationInfo?> GetAsync(
        Guid conversationId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<IntakeConversationInfo>> ListAsync(
        int skip = 0,
        int take = 20,
        CancellationToken cancellationToken = default);

    // Messages are returned in ascending SequenceNumber order.
    Task<IntakeMessagePage> GetMessagesAsync(
        Guid conversationId,
        long afterSequenceNumber = 0,
        int take = 50,
        CancellationToken cancellationToken = default);

    // Saves only a reporter message. Role and author are server-assigned.
    // Retrying the same operation with identical content returns the saved
    // message; different content with the same operationId must be rejected.
    Task<IntakeMessageInfo> AppendReporterMessageAsync(
        Guid conversationId,
        Guid operationId,
        string content,
        CancellationToken cancellationToken = default);
}

public sealed record IntakeConversationInfo(
    Guid Id,
    string Title,
    IntakeConversationStatus Status,
    Guid? CyberCaseId,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc);

public sealed record IntakeMessageInfo(
    Guid Id,
    long SequenceNumber,
    IntakeMessageRole Role,
    string Content,
    Guid OperationId,
    DateTime CreatedAtUtc);

public sealed record IntakeMessagePage(
    IReadOnlyList<IntakeMessageInfo> Messages,
    bool HasMore,
    long NextAfterSequenceNumber);