using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ACCP.Domain.Entities;

public sealed class IntakeRiskAssessment
{
    public Guid Id { get; private set; } = Guid.NewGuid();

    public Guid ConversationId { get; private set; }

    public Guid AssistantMessageId { get; private set; }

    public long BasedOnSequenceNumber { get; private set; }

    [Required, MaxLength(200)]
    public string Title { get; private set; } = string.Empty;

    [Required, MaxLength(4000)]
    public string Summary { get; private set; } = string.Empty;

    [Required, MaxLength(50)]
    public string IncidentType { get; private set; } = string.Empty;

    public decimal RiskPercentage { get; private set; }

    [Required, MaxLength(2000)]
    public string RiskExplanation { get; private set; } = string.Empty;

    public DateTime CreatedAtUtc { get; private set; } = DateTime.UtcNow;

    [NotMapped]
    public bool ShouldOfferFormalReport => RiskPercentage > 80m;

    private IntakeRiskAssessment()
    {
    }

    public IntakeRiskAssessment(
        Guid conversationId,
        Guid assistantMessageId,
        long basedOnSequenceNumber,
        string title,
        string summary,
        string incidentType,
        decimal riskPercentage,
        string riskExplanation)
    {
        if (conversationId == Guid.Empty)
        {
            throw new ArgumentException(
                "Conversation ID is required.",
                nameof(conversationId));
        }

        if (assistantMessageId == Guid.Empty)
        {
            throw new ArgumentException(
                "Assistant message ID is required.",
                nameof(assistantMessageId));
        }

        if (basedOnSequenceNumber <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(basedOnSequenceNumber));
        }

        if (riskPercentage is < 0m or > 100m)
        {
            throw new ArgumentOutOfRangeException(
                nameof(riskPercentage));
        }

        if (incidentType is not (
            "Blackmail" or
            "Fraud" or
            "AccountHacking" or
            "IdentityTheft" or
            "Threat" or
            "Other"))
        {
            throw new ArgumentException(
                "Unsupported incident type.",
                nameof(incidentType));
        }

        Title = RequireText(
            title, 3, 200, nameof(title));

        Summary = RequireText(
            summary, 10, 4000, nameof(summary));

        RiskExplanation = RequireText(
            riskExplanation, 1, 2000, nameof(riskExplanation));

        ConversationId = conversationId;
        AssistantMessageId = assistantMessageId;
        BasedOnSequenceNumber = basedOnSequenceNumber;
        IncidentType = incidentType;
        RiskPercentage = riskPercentage;
    }

    private static string RequireText(
        string value,
        int minimum,
        int maximum,
        string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);

        var text = value.Trim();

        if (text.Length < minimum || text.Length > maximum)
        {
            throw new ArgumentException(
                $"Text length must be between {minimum} and {maximum} characters.",
                parameterName);
        }

        return text;
    }
}