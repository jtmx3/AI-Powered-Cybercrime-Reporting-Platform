namespace ACCP.Application.EvidenceManagement;

public class EvidenceUploadRequest
{
    public Guid CyberCaseId { get; set; }

    public string OriginalFileName { get; set; } = string.Empty;

    public string ContentType { get; set; } = string.Empty;

    public long FileSizeBytes { get; set; }

    public Stream Content { get; set; } = Stream.Null;

    public bool IsRestricted { get; set; }
}