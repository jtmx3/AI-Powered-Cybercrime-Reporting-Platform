using System;
using System.Threading;
using System.Threading.Tasks;

namespace ACCP.Application.Chat;

/// <summary>
/// Generates and persists assistant replies for the authenticated reporter.
/// Ownership and the account's current permissions must be checked on every call.
/// </summary>
public interface IIntakeAssistantWorkflow
{
    /// <summary>
    /// Reads the conversation from the database and replies to an existing
    /// reporter message identified by operationId.
    ///
    /// A retry returns the already persisted reply when one exists.
    /// New replies to an outdated reporter message must be rejected.
    /// The assistant reply and its optional assessment are saved atomically.
    ///
    /// Model failures leave the reporter message available for retry.
    /// This method does not create a formal report or assign an officer.
    /// </summary>
    Task<IntakeAssistantTurn> ReplyAsync(
        Guid conversationId,
        Guid operationId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the assessment applicable to the latest reporter message.
    /// Returns null when there is no assessment for that message.
    /// Earlier assessments remain historical and cannot authorize a report.
    /// Inaccessible conversations must be rejected.
    /// </summary>
    Task<IntakeAssessmentInfo?> GetCurrentAssessmentAsync(
        Guid conversationId,
        CancellationToken cancellationToken = default);
}

public sealed record IntakeAssistantTurn(
    IntakeMessageInfo Message,
    IntakeAssessmentInfo? Assessment);

public sealed record IntakeAssessmentInfo(
    Guid Id,
    Guid AssistantMessageId,
    long BasedOnSequenceNumber,
    CaseRiskAssessment Assessment,
    DateTime CreatedAtUtc);