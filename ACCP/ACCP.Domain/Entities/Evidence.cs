using ACCP.Domain.Enums;

namespace ACCP.Domain.Entities;

public class Evidence
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string OriginalFileName { get; set; } =
        string.Empty;

    public string StorageKey { get; set; } =
        string.Empty;

    public string ContentType { get; set; } =
        string.Empty;

    public long FileSizeBytes { get; set; }

    public EvidenceType Type { get; set; } =
        EvidenceType.Other;

    public string Sha256Hash { get; set; } =
        string.Empty;

    // يحدد أن الدليل حساس ومخفي عن الموظف افتراضيًا.
    public bool IsRestricted { get; set; }

    // يصبح true فقط بعد موافقة المشتكي الصريحة.
    public bool IsDisclosedToOfficer { get; set; }

    // وقت موافقة المشتكي على كشف الدليل.
    public DateTime? DisclosedToOfficerAtUtc { get; set; }

    // معرّف المشتكي الذي نفّذ الموافقة.
    public Guid? DisclosedByReporterId { get; set; }

    public DateTime UploadedAtUtc { get; set; } =
        DateTime.UtcNow;

    public Guid CyberCaseId { get; set; }

    public CyberCase CyberCase { get; set; } =
        null!;
    public List<EvidenceRevision> Revisions { get; set; } =
    [];
}