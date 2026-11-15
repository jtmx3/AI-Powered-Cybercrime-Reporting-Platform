using System.ComponentModel.DataAnnotations;
using ACCP.Domain.Enums;

namespace ACCP.Domain.Entities;

public class CyberCase
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [StringLength(50)]
    public string CaseNumber { get; set; } =
        string.Empty;

    [Required(ErrorMessage = "عنوان القضية مطلوب.")]
    [StringLength(
        200,
        MinimumLength = 3,
        ErrorMessage =
            "عنوان القضية يجب أن يكون بين 3 و200 حرف.")]
    public string Title { get; set; } =
        string.Empty;

    [Required(ErrorMessage = "وصف المشكلة مطلوب.")]
    [StringLength(
        4000,
        MinimumLength = 10,
        ErrorMessage =
            "وصف المشكلة يجب أن يحتوي على 10 أحرف على الأقل.")]
    public string Description { get; set; } =
        string.Empty;

    [Required(ErrorMessage = "يجب اختيار نوع الحادثة.")]
    [StringLength(50)]
    public string IncidentType { get; set; } =
        string.Empty;

    public SeverityLevel SeverityLevel { get; set; } =
        SeverityLevel.Low;

    public CaseStatus Status { get; set; } =
        CaseStatus.New;

    // Existing creation flows continue to create formal reports by default.
    public CasePath Path { get; set; } =
        CasePath.FormalReport;

    public DateTime CreatedAtUtc { get; set; } =
        DateTime.UtcNow;

    // يبقى داخليًا ولا يُعرض للموظف
    public Guid? ReporterId { get; set; }

    // هل وافق المشتكي صراحة على إظهار هويته؟
    public bool IsReporterIdentityDisclosed { get; set; }

    [StringLength(256)]
    public string? DisclosedReporterName { get; set; }

    [StringLength(256)]
    public string? DisclosedReporterEmail { get; set; }

    public DateTime? ReporterIdentityDisclosedAtUtc
    {
        get;
        set;
    }

    public Guid? AssignedOfficerId { get; set; }

    [StringLength(256)]
    public string? AssignedOfficerEmail { get; set; }

    public DateTime? AssignedAtUtc { get; set; }

    public List<Evidence> EvidenceItems { get; set; } =
        [];

    public List<CaseStatusHistory> StatusHistory
    {
        get;
        set;
    } = [];

    public List<CaseNote> InternalNotes { get; set; } =
        [];

    public List<CaseMessage> Messages { get; set; } =
        [];

    public List<CaseStaffRequest> StaffRequests { get; set; } =
        [];

    public List<CaseCollaborator> Collaborators { get; set; } =
        [];
}