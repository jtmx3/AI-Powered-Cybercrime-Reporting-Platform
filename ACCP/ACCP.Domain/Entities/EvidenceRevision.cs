using System.ComponentModel.DataAnnotations;
using ACCP.Domain.Enums;

namespace ACCP.Domain.Entities;

public class EvidenceRevision
{
    public Guid Id { get; set; } =
        Guid.NewGuid();

    public Guid EvidenceId { get; set; }

    public Evidence Evidence { get; set; } =
        null!;

    public int VersionNumber { get; set; }

    [Required]
    [StringLength(256)]
    public string OriginalFileName { get; set; } =
        string.Empty;

    [Required]
    [StringLength(500)]
    public string StorageKey { get; set; } =
        string.Empty;

    [Required]
    [StringLength(100)]
    public string ContentType { get; set; } =
        string.Empty;

    public long FileSizeBytes { get; set; }

    public EvidenceType Type { get; set; } =
        EvidenceType.Other;

    [Required]
    [StringLength(64)]
    public string Sha256Hash { get; set; } =
        string.Empty;

    public EvidenceChangeType ChangeType { get; set; }

    [Required]
    [StringLength(
        1000,
        MinimumLength = 10)]
    public string ChangeReason { get; set; } =
        string.Empty;

    public Guid ChangedByReporterId { get; set; }

    // يثبت أن المشتكي قرأ ووافق على أن النسخة الأصلية
    // والنسخ السابقة تبقى متاحة للموظف المخوّل والمدير.
    public bool IsOriginalEvidenceAccessAcknowledged
    {
        get;
        set;
    }

    // وقت إعطاء الموافقة، ويُحفظ بالتوقيت العالمي UTC.
    public DateTime?
        OriginalEvidenceAccessAcknowledgedAtUtc
    {
        get;
        set;
    }

    // نحفظ نص التحذير الذي وافق عليه المشتكي
    // لإثبات مضمون الموافقة حتى لو تغيّر النص مستقبلًا.
    [StringLength(1000)]
    public string?
        OriginalEvidenceAccessAcknowledgementText
    {
        get;
        set;
    }

    public DateTime CreatedAtUtc { get; set; } =
        DateTime.UtcNow;
}
