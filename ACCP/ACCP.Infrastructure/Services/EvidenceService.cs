using System.Data;
using System.Security.Cryptography;
using ACCP.Application.Auditing;
using ACCP.Application.EvidenceManagement;
using ACCP.Application.Security;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using EvidenceEntity = ACCP.Domain.Entities.Evidence;
using EvidenceRevisionEntity = ACCP.Domain.Entities.EvidenceRevision;
namespace ACCP.Infrastructure.Services;
public class EvidenceService : IEvidenceService
{
    private const long MaximumFileSize = 10 * 1024 * 1024;
    private readonly AccpDbContext _dbContext;
    private readonly IHostEnvironment _environment;
    private readonly IAuditService _auditService;
    private readonly IDataEncryptionService? _encryptionService;
    private readonly IEvidenceMalwareScanner _malwareScanner;
    public EvidenceService(
        AccpDbContext dbContext,
        IHostEnvironment environment,
        IAuditService auditService,
        IDataEncryptionService? encryptionService = null,
        IEvidenceMalwareScanner? malwareScanner = null)
    {
        _dbContext = dbContext;
        _environment = environment;
        _auditService = auditService;
        _encryptionService = encryptionService;
        _malwareScanner = malwareScanner ?? new HeuristicEvidenceMalwareScanner();
    }
    public async Task<EvidenceRevisionEntity> UploadRevisionAsync(
        EvidenceRevisionUploadRequest request,
        Guid reporterId)
    {
        ValidateRevisionRequest(request, reporterId);
        var originalEvidenceDetails =
            await _dbContext.EvidenceItems
                .Where(evidence =>
                    evidence.Id == request.EvidenceId &&
                    evidence.CyberCase.ReporterId == reporterId)
                .Select(evidence => new
                {
                    Evidence = evidence,
                    Path = evidence.CyberCase.Path
                })
                .FirstOrDefaultAsync();
        if (originalEvidenceDetails is null)
        {
            await WriteAccessDeniedAuditAsync(
                reporterId,
                null,
                request.EvidenceId,
                "تم رفض محاولة تعديل دليل لعدم امتلاك الصلاحية.",
                "الدليل غير موجود أو لا يملك المستخدم صلاحية تعديله.");
            throw new UnauthorizedAccessException(
                "الدليل غير موجود أو لا تملك صلاحية تعديله.");
        }
        EvidenceEntity originalEvidence = originalEvidenceDetails.Evidence;
        // Read Path from the database projection, even if the case is already tracked.
        bool isFormalReport = originalEvidenceDetails.Path == CasePath.FormalReport;
        if (isFormalReport && !request.IsOriginalEvidenceAccessAcknowledged)
        {
            throw new InvalidOperationException(
                "يجب قراءة التحذير والموافقة عليه قبل تعديل الدليل.");
        }
        string cleanReason = request.ChangeReason.Trim();
        string safeOriginalFileName =
            Path.GetFileName(request.OriginalFileName);
        string extension =
            Path.GetExtension(safeOriginalFileName)
                .ToLowerInvariant();
        byte[] fileBytes =
            await ReadFileSafelyAsync(request.Content);
        if (fileBytes.LongLength != request.FileSizeBytes)
        {
            throw new InvalidOperationException(
                "حجم الملف الفعلي لا يطابق الحجم المرسل.");
        }
        (EvidenceType evidenceType, string safeContentType) =
            DetectAndValidateFile(fileBytes, extension);
        var scanResult = await _malwareScanner.ScanAsync(fileBytes, extension);
        if (!scanResult.IsClean)
        {
            await WriteAccessDeniedAuditAsync(
                reporterId,
                originalEvidence.CyberCaseId,
                originalEvidence.Id,
                "تم رفض نسخة دليل بعد فشل الفحص الأمني للملف.",
                scanResult.ThreatName ?? "Malicious payload detected.");
            throw new InvalidOperationException(
                scanResult.Reason ?? "تم رفض الملف بعد الفحص الأمني.");
        }
        fileBytes = EvidenceMetadataSanitizer.SanitizeAndValidate(fileBytes, extension);
        if (request.ChangeType ==
                EvidenceChangeType.ModifiedVersion &&
            evidenceType != originalEvidence.Type)
        {
            throw new InvalidOperationException(
                "النسخة المعدلة يجب أن تكون من نفس نوع الدليل الأصلي.");
        }
        string sha256Hash =
            Convert.ToHexString(SHA256.HashData(fileBytes));
        string? latestHash =
            await _dbContext.EvidenceRevisions
                .AsNoTracking()
                .Where(revision =>
                    revision.EvidenceId == originalEvidence.Id)
                .OrderByDescending(revision =>
                    revision.VersionNumber)
                .Select(revision => revision.Sha256Hash)
                .FirstOrDefaultAsync();
        latestHash ??= originalEvidence.Sha256Hash;
        if (string.Equals(
                latestHash,
                sha256Hash,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "الملف الجديد مطابق تمامًا لآخر نسخة محفوظة.");
        }
        string storedFileName =
            $"{Guid.NewGuid():N}{extension}";
        string caseFolderName =
            originalEvidence.CyberCaseId.ToString("N");
        string evidenceFolderName =
            originalEvidence.Id.ToString("N");
        string storageDirectory = Path.Combine(
            _environment.ContentRootPath,
            "App_Data",
            "Evidence",
            caseFolderName,
            "Revisions",
            evidenceFolderName);
        Directory.CreateDirectory(storageDirectory);
        string fullFilePath = Path.Combine(
            storageDirectory,
            storedFileName);
        string storageKey =
            $"{caseFolderName}/Revisions/" +
            $"{evidenceFolderName}/{storedFileName}";
        byte[] bytesToPersist = _encryptionService is not null
            ? _encryptionService.EncryptBytes(fileBytes, AesGcmDataEncryptionService.EvidenceFilePurpose)
            : fileBytes;
        try
        {
            await File.WriteAllBytesAsync(
                fullFilePath,
                bytesToPersist);
            await using var transaction =
                await _dbContext.Database
                    .BeginTransactionAsync(
                        IsolationLevel.Serializable);
            try
            {
                int latestVersion =
                    await _dbContext.EvidenceRevisions
                        .Where(revision =>
                            revision.EvidenceId ==
                                originalEvidence.Id)
                        .Select(revision =>
                            (int?)revision.VersionNumber)
                        .MaxAsync()
                    ?? 1;

                DateTime createdAtUtc =
                    DateTime.UtcNow;

                bool disclosureGrantedByAcknowledgement =
                    isFormalReport &&
                    originalEvidence.IsRestricted &&
                    !originalEvidence.IsDisclosedToOfficer;

                if (disclosureGrantedByAcknowledgement)
                {
                    originalEvidence.IsDisclosedToOfficer = true;
                    originalEvidence.DisclosedToOfficerAtUtc =
                        createdAtUtc;
                    originalEvidence.DisclosedByReporterId =
                        reporterId;
                }

                var revision = new EvidenceRevisionEntity
                {
                    EvidenceId = originalEvidence.Id,
                    VersionNumber = latestVersion + 1,
                    OriginalFileName = safeOriginalFileName,
                    StorageKey = storageKey,
                    ContentType = safeContentType,
                    FileSizeBytes = fileBytes.LongLength,
                    Type = evidenceType,
                    Sha256Hash = sha256Hash,
                    ChangeType = request.ChangeType,
                    ChangeReason = cleanReason,
                    ChangedByReporterId = reporterId,
                    IsOriginalEvidenceAccessAcknowledged =
                        isFormalReport,
                    OriginalEvidenceAccessAcknowledgedAtUtc =
                        isFormalReport ? createdAtUtc : null,
                    OriginalEvidenceAccessAcknowledgementText =
                        isFormalReport
                            ? EvidenceRevisionUploadRequest.OriginalEvidenceAccessAcknowledgementText
                            : null,
                    CreatedAtUtc = createdAtUtc
                };
                _dbContext.EvidenceRevisions.Add(revision);

                if (disclosureGrantedByAcknowledgement)
                {
                    await _auditService.WriteAsync(
                        new AuditLogRequest
                        {
                            Action =
                                AuditAction.EvidenceDisclosureGranted,
                            ActorUserId = reporterId,
                            ActorRole = "USER",
                            CyberCaseId =
                                originalEvidence.CyberCaseId,
                            EntityType = nameof(EvidenceEntity),
                            EntityId = originalEvidence.Id,
                            Description =
                                "وافق المشتكي أثناء تعديل الدليل " +
                                "على إتاحة النسخة الأصلية والنسخ " +
                                "السابقة للموظف المخوّل.",
                            IsSuccessful = true
                        });
                }

                await _auditService.WriteAsync(
                    new AuditLogRequest
                    {
                        Action = AuditAction.EvidenceRevisionUploaded,
                        ActorUserId = reporterId,
                        ActorRole = "USER",
                        CyberCaseId =
                            originalEvidence.CyberCaseId,
                        EntityType =
                            nameof(EvidenceRevisionEntity),
                        EntityId = revision.Id,
                        Description =
                            isFormalReport
                                ? $"تم رفع النسخة رقم " +
                                  $"{revision.VersionNumber} من الدليل " +
                                  "بعد موافقة المشتكي على إشعار " +
                                  "الاحتفاظ والوصول."
                                : $"تم رفع النسخة رقم {revision.VersionNumber} من مرفق طلب المساعدة.",
                        IsSuccessful = true
                    });
                await transaction.CommitAsync();
                return revision;
            }
            catch
            {
                await transaction.RollbackAsync();
                throw;
            }
        }
        catch
        {
            if (File.Exists(fullFilePath))
            {
                File.Delete(fullFilePath);
            }
            throw;
        }
    }
    public async Task<EvidenceEntity> UploadAsync(
        EvidenceUploadRequest request,
        Guid reporterId)
    {
        ValidateRequest(request, reporterId);
        bool userOwnsCase =
            await _dbContext.CyberCases
                .AsNoTracking()
                .AnyAsync(cyberCase =>
                    cyberCase.Id == request.CyberCaseId &&
                    cyberCase.ReporterId == reporterId);
        if (!userOwnsCase)
        {
            await WriteAccessDeniedAuditAsync(
                reporterId,
                request.CyberCaseId,
                null,
                "تم رفض محاولة رفع دليل إلى قضية غير مملوكة للمستخدم.",
                "القضية غير موجودة أو لا يملك المستخدم صلاحية الوصول إليها.");
            throw new UnauthorizedAccessException(
                "القضية غير موجودة أو لا تملك صلاحية الوصول إليها.");
        }
        string safeOriginalFileName =
            Path.GetFileName(request.OriginalFileName);
        string extension =
            Path.GetExtension(safeOriginalFileName)
                .ToLowerInvariant();
        byte[] fileBytes =
            await ReadFileSafelyAsync(request.Content);
        if (fileBytes.LongLength != request.FileSizeBytes)
        {
            throw new InvalidOperationException(
                "حجم الملف الفعلي لا يطابق الحجم المرسل.");
        }
        (EvidenceType evidenceType, string safeContentType) =
            DetectAndValidateFile(fileBytes, extension);
        var scanResult = await _malwareScanner.ScanAsync(fileBytes, extension);
        if (!scanResult.IsClean)
        {
            await WriteAccessDeniedAuditAsync(
                reporterId,
                request.CyberCaseId,
                null,
                "تم رفض دليل مرفوع بعد فشل الفحص الأمني للملف.",
                scanResult.ThreatName ?? "Malicious payload detected.");
            throw new InvalidOperationException(
                scanResult.Reason ?? "تم رفض الملف بعد الفحص الأمني.");
        }
        fileBytes = EvidenceMetadataSanitizer.SanitizeAndValidate(fileBytes, extension);
        string sha256Hash =
            Convert.ToHexString(SHA256.HashData(fileBytes));
        string storedFileName =
            $"{Guid.NewGuid():N}{extension}";
        string caseFolderName =
            request.CyberCaseId.ToString("N");
        string storageDirectory = Path.Combine(
            _environment.ContentRootPath,
            "App_Data",
            "Evidence",
            caseFolderName);
        Directory.CreateDirectory(storageDirectory);
        string fullFilePath = Path.Combine(
            storageDirectory,
            storedFileName);
        string storageKey =
            $"{caseFolderName}/{storedFileName}";
        byte[] bytesToPersist = _encryptionService is not null
            ? _encryptionService.EncryptBytes(fileBytes, AesGcmDataEncryptionService.EvidenceFilePurpose)
            : fileBytes;
        await File.WriteAllBytesAsync(
            fullFilePath,
            bytesToPersist);
        var evidence = new EvidenceEntity
        {
            OriginalFileName = safeOriginalFileName,
            StorageKey = storageKey,
            ContentType = safeContentType,
            FileSizeBytes = fileBytes.LongLength,
            Type = evidenceType,
            Sha256Hash = sha256Hash,
            IsRestricted = request.IsRestricted,
            CyberCaseId = request.CyberCaseId
        };
        try
        {
            _dbContext.EvidenceItems.Add(evidence);
            await _auditService.WriteAsync(
                new AuditLogRequest
                {
                    Action = AuditAction.EvidenceUploaded,
                    ActorUserId = reporterId,
                    ActorRole = "USER",
                    CyberCaseId = request.CyberCaseId,
                    EntityType = nameof(EvidenceEntity),
                    EntityId = evidence.Id,
                    Description =
                        "تم رفع دليل جديد إلى القضية.",
                    IsSuccessful = true
                });
            return evidence;
        }
        catch
        {
            if (File.Exists(fullFilePath))
            {
                File.Delete(fullFilePath);
            }
            throw;
        }
    }
    public async Task<List<EvidenceEntity>> GetByCaseIdAsync(
        Guid cyberCaseId,
        Guid reporterId)
    {
        if (cyberCaseId == Guid.Empty ||
            reporterId == Guid.Empty)
        {
            return [];
        }
        bool userOwnsCase =
            await _dbContext.CyberCases
                .AsNoTracking()
                .AnyAsync(cyberCase =>
                    cyberCase.Id == cyberCaseId &&
                    cyberCase.ReporterId == reporterId);
        if (!userOwnsCase)
        {
            await WriteAccessDeniedAuditAsync(
                reporterId,
                cyberCaseId,
                null,
                "تم رفض محاولة الوصول إلى قائمة أدلة قضية غير مملوكة للمستخدم.",
                "لا يملك المستخدم صلاحية الوصول إلى القضية.");
            return [];
        }
        return await _dbContext.EvidenceItems
            .AsNoTracking()
            .Where(evidence =>
                evidence.CyberCaseId == cyberCaseId)
            .OrderByDescending(evidence =>
                evidence.UploadedAtUtc)
            .ToListAsync();
    }
    public async Task<bool> DiscloseToOfficerAsync(
        Guid evidenceId,
        Guid reporterId)
    {
        if (evidenceId == Guid.Empty ||
            reporterId == Guid.Empty)
        {
            return false;
        }
        EvidenceEntity? evidence =
            await _dbContext.EvidenceItems
                .FirstOrDefaultAsync(evidence =>
                    evidence.Id == evidenceId &&
                    evidence.CyberCase.Path == CasePath.FormalReport &&
                    evidence.CyberCase.ReporterId ==
                        reporterId);
        if (evidence is null)
        {
            await WriteAccessDeniedAuditAsync(
                reporterId,
                null,
                evidenceId,
                "تم رفض محاولة الإفصاح عن دليل غير متاح للكشف للموظفين.",
                "الدليل غير موجود أو غير مملوك للمستخدم أو لا يتبع بلاغًا رسميًا.");
            return false;
        }
        // الموافقة مخصصة للأدلة المقيدة فقط.
        if (!evidence.IsRestricted)
        {
            return false;
        }
        // إذا تمت الموافقة سابقًا فلا نكرر العملية أو سجل التدقيق.
        if (evidence.IsDisclosedToOfficer)
        {
            return true;
        }
        evidence.IsDisclosedToOfficer = true;
        evidence.DisclosedToOfficerAtUtc = DateTime.UtcNow;
        evidence.DisclosedByReporterId = reporterId;
        await _auditService.WriteAsync(
            new AuditLogRequest
            {
                Action =
                    AuditAction.EvidenceDisclosureGranted,
                ActorUserId = reporterId,
                ActorRole = "USER",
                CyberCaseId = evidence.CyberCaseId,
                EntityType = nameof(EvidenceEntity),
                EntityId = evidence.Id,
                Description =
                    "وافق المشتكي على إظهار الدليل للموظف المسؤول.",
                IsSuccessful = true
            });
        return true;
    }
    private async Task WriteAccessDeniedAuditAsync(
        Guid actorUserId,
        Guid? cyberCaseId,
        Guid? entityId,
        string description,
        string failureReason)
    {
        await _auditService.WriteAsync(
            new AuditLogRequest
            {
                Action = AuditAction.AccessDenied,
                ActorUserId =
                    actorUserId == Guid.Empty
                        ? (Guid?)null
                        : actorUserId,
                ActorRole = "USER",
                CyberCaseId = cyberCaseId,
                EntityType = nameof(EvidenceEntity),
                EntityId = entityId,
                Description = description,
                IsSuccessful = false,
                FailureReason = failureReason
            });
    }
    private static void ValidateRevisionRequest(
        EvidenceRevisionUploadRequest request,
        Guid reporterId)
    {
        if (reporterId == Guid.Empty)
        {
            throw new UnauthorizedAccessException(
                "يجب تسجيل الدخول لتعديل الدليل.");
        }

        if (request.EvidenceId == Guid.Empty)
        {
            throw new InvalidOperationException(
                "معرّف الدليل غير صالح.");
        }
        if (string.IsNullOrWhiteSpace(
                request.OriginalFileName))
        {
            throw new InvalidOperationException(
                "اسم الملف الجديد غير صالح.");
        }
        if (request.Content is null)
        {
            throw new InvalidOperationException(
                "محتوى الملف الجديد غير موجود.");
        }
        if (request.FileSizeBytes <= 0)
        {
            throw new InvalidOperationException(
                "الملف الجديد فارغ.");
        }
        if (request.FileSizeBytes > MaximumFileSize)
        {
            throw new InvalidOperationException(
                "حجم الملف الجديد يتجاوز الحد المسموح.");
        }
        if (!Enum.IsDefined(
                typeof(EvidenceChangeType),
                request.ChangeType))
        {
            throw new InvalidOperationException(
                "نوع التغيير غير صالح.");
        }
        string cleanReason =
            request.ChangeReason?.Trim()
            ?? string.Empty;
        if (cleanReason.Length < 10)
        {
            throw new InvalidOperationException(
                "يجب كتابة سبب واضح للتغيير لا يقل عن 10 أحرف.");
        }
        if (cleanReason.Length > 1000)
        {
            throw new InvalidOperationException(
                "سبب التغيير يتجاوز 1000 حرف.");
        }
    }
    private static void ValidateRequest(
        EvidenceUploadRequest request,
        Guid reporterId)
    {
        if (reporterId == Guid.Empty)
        {
            throw new UnauthorizedAccessException(
                "يجب تسجيل الدخول لرفع الأدلة.");
        }
        if (request.CyberCaseId == Guid.Empty)
        {
            throw new InvalidOperationException(
                "رقم القضية غير صالح.");
        }
        if (string.IsNullOrWhiteSpace(
                request.OriginalFileName))
        {
            throw new InvalidOperationException(
                "اسم الملف غير صالح.");
        }
        if (request.Content is null)
        {
            throw new InvalidOperationException(
                "محتوى الملف غير موجود.");
        }
        if (request.FileSizeBytes <= 0)
        {
            throw new InvalidOperationException(
                "الملف فارغ.");
        }
        if (request.FileSizeBytes > MaximumFileSize)
        {
            throw new InvalidOperationException(
                "حجم الملف يتجاوز الحد المسموح.");
        }
    }
    private static async Task<byte[]> ReadFileSafelyAsync(
        Stream content)
    {
        using var memoryStream = new MemoryStream();
        byte[] buffer = new byte[81920];
        long totalBytes = 0;
        while (true)
        {
            int bytesRead = await content.ReadAsync(buffer);
            if (bytesRead == 0)
            {
                break;
            }
            totalBytes += bytesRead;
            if (totalBytes > MaximumFileSize)
            {
                throw new InvalidOperationException(
                    "حجم الملف يتجاوز الحد المسموح.");
            }
            await memoryStream.WriteAsync(
                buffer.AsMemory(0, bytesRead));
        }
        if (totalBytes == 0)
        {
            throw new InvalidOperationException(
                "الملف فارغ.");
        }
        return memoryStream.ToArray();
    }
    private static (
        EvidenceType EvidenceType,
        string ContentType)
        DetectAndValidateFile(
            byte[] fileBytes,
            string extension)
    {
        bool isPng =
            fileBytes.Length >= 8 &&
            fileBytes[0] == 0x89 &&
            fileBytes[1] == 0x50 &&
            fileBytes[2] == 0x4E &&
            fileBytes[3] == 0x47 &&
            fileBytes[4] == 0x0D &&
            fileBytes[5] == 0x0A &&
            fileBytes[6] == 0x1A &&
            fileBytes[7] == 0x0A;
        bool isJpeg =
            fileBytes.Length >= 3 &&
            fileBytes[0] == 0xFF &&
            fileBytes[1] == 0xD8 &&
            fileBytes[2] == 0xFF;
        bool isPdf =
            fileBytes.Length >= 4 &&
            fileBytes[0] == 0x25 &&
            fileBytes[1] == 0x50 &&
            fileBytes[2] == 0x44 &&
            fileBytes[3] == 0x46;
        if (extension == ".png" && isPng)
        {
            return (
                EvidenceType.Image,
                "image/png");
        }
        if ((extension == ".jpg" ||
             extension == ".jpeg") &&
            isJpeg)
        {
            return (
                EvidenceType.Image,
                "image/jpeg");
        }
        if (extension == ".pdf" && isPdf)
        {
            return (
                EvidenceType.Document,
                "application/pdf");
        }
        throw new InvalidOperationException(
            "نوع الملف غير مسموح أو محتواه لا يطابق امتداده.");
    }
}
