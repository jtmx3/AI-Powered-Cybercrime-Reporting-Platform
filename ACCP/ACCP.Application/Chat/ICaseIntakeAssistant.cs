namespace ACCP.Application.Chat;

/// <summary>
/// Receives the conversation and returns the assistant's next reply.
/// The implementation supplies the AI assessment; the user never supplies a risk score.
/// This service does not create a report, assign an officer, or grant staff access.
/// </summary>
public interface ICaseIntakeAssistant
{
    Task<IntakeAssistantReply> ReplyAsync(
        IReadOnlyList<IntakeChatMessage> conversation,
        CancellationToken cancellationToken = default);
}

public enum IntakeChatRole
{
    User,
    Assistant
}

public sealed record IntakeChatMessage(IntakeChatRole Role, string Content);

/// <summary>
/// Assessment remains null while the assistant needs more information.
/// An unavailable or invalid model response must produce an error, never a fabricated score.
/// </summary>
public sealed record IntakeAssistantReply(
    string Message,
    CaseRiskAssessment? Assessment = null)
{
    public bool ShouldOfferFormalReport => Assessment?.ShouldOfferFormalReport == true;
}

/// <summary>
/// A model-generated assessment of a sufficiently described incident.
/// RiskPercentage is an estimated risk score, not a calibrated probability of a crime.
/// </summary>
public sealed class CaseRiskAssessment
{
    public const decimal FormalReportThreshold = 80m;

    public string Title { get; }
    public string Summary { get; }
    public string IncidentType { get; }
    public decimal RiskPercentage { get; }
    public string RiskExplanation { get; }

    // Exactly 80% does not qualify: the user's rule is strictly greater than 80%.
    // Offering a report does not submit it. Submission requires the user's explicit "yes".
    public bool ShouldOfferFormalReport => RiskPercentage > FormalReportThreshold;

    public CaseRiskAssessment(
        string title,
        string summary,
        string incidentType,
        decimal riskPercentage,
        string riskExplanation)
    {
        if (riskPercentage is < 0m or > 100m)
            throw new ArgumentOutOfRangeException(nameof(riskPercentage), "Risk score must be between 0 and 100.");

        if (incidentType is not ("Blackmail" or "Fraud" or "AccountHacking" or "IdentityTheft" or "Threat" or "Other"))
            throw new ArgumentException("Incident type must match a supported case type.", nameof(incidentType));

        Title = RequiredText(title, 3, 200, nameof(title));
        Summary = RequiredText(summary, 10, 4000, nameof(summary));
        RiskExplanation = RequiredText(riskExplanation, 1, 2000, nameof(riskExplanation));
        IncidentType = incidentType;
        RiskPercentage = riskPercentage;
    }

    private static string RequiredText(string value, int minimum, int maximum, string parameter)
    {
        ArgumentNullException.ThrowIfNull(value, parameter);
        var text = value.Trim();
        if (text.Length < minimum || text.Length > maximum)
            throw new ArgumentException($"Text length must be between {minimum} and {maximum} characters.", parameter);
        return text;
    }
}