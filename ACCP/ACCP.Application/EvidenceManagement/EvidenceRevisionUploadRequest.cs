using System.ComponentModel.DataAnnotations;
using ACCP.Domain.Enums;

namespace ACCP.Application.EvidenceManagement;

public class EvidenceRevisionUploadRequest
{
    public const string
        OriginalEvidenceAccessAcknowledgementText =
            "أفهم أن النسخة الأصلية والنسخ السابقة من هذا الدليل " +
            "ستبقى محفوظة، وسيتمكن الموظف المخوّل بالقضية " +
            "ومدير النظام من الوصول إليها ومراجعتها " +
            "لأغراض التحقيق والتدقيق.";

    public Guid EvidenceId { get; set; }

    [Required]
    [StringLength(256)]
    public string OriginalFileName { get; set; } =
        string.Empty;

    public long FileSizeBytes { get; set; }

    public Stream Content { get; set; } =
        Stream.Null;

    public EvidenceChangeType ChangeType { get; set; }

    [Required]
    [StringLength(
        1000,
        MinimumLength = 10,
        ErrorMessage =
            "سبب التغيير يجب أن يحتوي على 10 أحرف على الأقل.")]
    public string ChangeReason { get; set; } =
        string.Empty;

    [Range(
        typeof(bool),
        "true",
        "true",
        ErrorMessage =
            "يجب قراءة التحذير والموافقة عليه قبل تعديل الدليل.")]
    public bool IsOriginalEvidenceAccessAcknowledged
    {
        get;
        set;
    }
}
