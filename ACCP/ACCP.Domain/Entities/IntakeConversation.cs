using System;
using System.ComponentModel.DataAnnotations;

namespace ACCP.Domain.Entities;

public enum IntakeConversationStatus
{
    Assistant = 0,
    AwaitingReportDecision = 1,
    AwaitingOfficer = 2,
    OfficerActive = 3,
    Closed = 4
}

public sealed class IntakeConversation
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ReporterId { get; set; }

    [MaxLength(200)]
    public string Title { get; set; } = "محادثة جديدة";

    public IntakeConversationStatus Status { get; set; } =
        IntakeConversationStatus.Assistant;

    // يبقى فارغًا حتى إنشاء البلاغ بموافقة المشتكي.
    public Guid? CyberCaseId { get; set; }

    public CyberCase? CyberCase { get; set; }

    // التقييم المحفوظ الذي وافق عليه المشتكي لتقديم البلاغ.
    // تعيّنه الخدمة على الخادم عند إتمام التقديم.
    public Guid? FormalReportAssessmentId { get; set; }

    // الموافقة على تقديم البلاغ لا تعني كشف الهوية أو الأدلة.
    public DateTime? FormalReportConsentAtUtc { get; set; }

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

    [Timestamp]
    public byte[] RowVersion { get; set; } = [];
}