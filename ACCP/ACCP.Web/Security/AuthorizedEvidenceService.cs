using ACCP.Application.Auditing;
using ACCP.Application.EvidenceManagement;
using ACCP.Application.Security;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;

namespace ACCP.Web.Security;

/// <summary>
/// Server-authorized evidence operations for the current reporter.
/// Register as IEvidenceService in Program.cs when this file has been added.
/// File downloads continue to use the separately protected HTTP endpoints.
/// </summary>
public sealed class AuthorizedEvidenceService : IEvidenceService
{
    private const long MaximumFileSize = 10 * 1024 * 1024;
    // Bulkhead: caps concurrent 10 MB evidence upload/sanitization/AES-GCM operations per node
    // to prevent Out-Of-Memory exhaustion under payload floods.
    private static readonly SemaphoreSlim UploadBulkhead = new(16, 16);
    private readonly CaseAuthorizationService _authorization;
    private readonly IServiceScopeFactory _scopeFactory;

    public AuthorizedEvidenceService(CaseAuthorizationService authorization, IServiceScopeFactory scopeFactory)
    {
        _authorization = authorization;
        _scopeFactory = scopeFactory;
    }

    public async Task<Evidence> UploadAsync(EvidenceUploadRequest request, Guid reporterId)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!await UploadBulkhead.WaitAsync(TimeSpan.FromSeconds(10)))
            throw new InvalidOperationException("الخادم مزدحم حالياً بمعالجة المرفقات. حاول مجدداً بعد لحظات.");
        try
        {
            // Capture mutable form values before awaiting authentication or reading a file.
            var clean = new EvidenceUploadRequest
            {
                CyberCaseId = request.CyberCaseId, OriginalFileName = request.OriginalFileName,
                ContentType = request.ContentType, FileSizeBytes = request.FileSizeBytes,
                Content = request.Content, IsRestricted = request.IsRestricted
            };
            await using var scope = _scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
            await RequireOwnedCaseAsync(scope.ServiceProvider, db, clean.CyberCaseId, reporterId);
            var bytes = await ReadBoundedAsync(clean.Content, clean.FileSizeBytes);
            // Reading a browser upload can take time. Check again before passing bytes
            // to the core service, which validates type/signature/hash and writes the file.
            var path = await RequireOwnedCaseAsync(scope.ServiceProvider, db, clean.CyberCaseId, reporterId);
            clean.IsRestricted = path == CasePath.Assistance || clean.IsRestricted;
            using var content = new MemoryStream(bytes, writable: false);
            clean.Content = content;
            return await Core(scope.ServiceProvider, db).UploadAsync(clean, reporterId);
        }
        finally
        {
            UploadBulkhead.Release();
        }
    }

    public async Task<List<Evidence>> GetByCaseIdAsync(Guid cyberCaseId, Guid reporterId)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        if (await OwnedCasePathAsync(scope.ServiceProvider, db, cyberCaseId, reporterId) is null)
            return [];
        return await Core(scope.ServiceProvider, db).GetByCaseIdAsync(cyberCaseId, reporterId);
    }

    public async Task<bool> DiscloseToOfficerAsync(Guid evidenceId, Guid reporterId)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var caseId = await OwnedEvidenceCaseAsync(scope.ServiceProvider, db, evidenceId, reporterId);
        if (caseId is null) return false;
        var path = await OwnedCasePathAsync(scope.ServiceProvider, db, caseId.Value, reporterId);
        if (path is null) return false;
        if (path != CasePath.FormalReport)
        {
            await DeniedAsync(scope.ServiceProvider, await _authorization.GetCurrentActorAsync(),
                caseId, evidenceId, "لا يجوز كشف مرفق طلب خاص للموظفين.");
            return false;
        }
        return await Core(scope.ServiceProvider, db).DiscloseToOfficerAsync(evidenceId, reporterId);
    }

    public async Task<EvidenceRevision> UploadRevisionAsync(EvidenceRevisionUploadRequest request, Guid reporterId)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!await UploadBulkhead.WaitAsync(TimeSpan.FromSeconds(10)))
            throw new InvalidOperationException("الخادم مزدحم حالياً بمعالجة المرفقات. حاول مجدداً بعد لحظات.");
        try
        {
            var clean = new EvidenceRevisionUploadRequest
            {
                EvidenceId = request.EvidenceId, OriginalFileName = request.OriginalFileName,
                FileSizeBytes = request.FileSizeBytes, Content = request.Content,
                ChangeType = request.ChangeType, ChangeReason = request.ChangeReason,
                IsOriginalEvidenceAccessAcknowledged = request.IsOriginalEvidenceAccessAcknowledged
            };
            await using var scope = _scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
            var caseId = await OwnedEvidenceCaseAsync(scope.ServiceProvider, db, clean.EvidenceId, reporterId);
            if (caseId is null) throw DeniedException();
            var path = await RequireOwnedCaseAsync(scope.ServiceProvider, db, caseId.Value, reporterId);
            if (path == CasePath.FormalReport && !clean.IsOriginalEvidenceAccessAcknowledged)
                throw new InvalidOperationException("يجب قراءة إشعار الاحتفاظ بالنسخ والموافقة عليه قبل تعديل الدليل.");
            var bytes = await ReadBoundedAsync(clean.Content, clean.FileSizeBytes);
            path = await RequireOwnedCaseAsync(scope.ServiceProvider, db, caseId.Value, reporterId);
            if (path == CasePath.FormalReport && !clean.IsOriginalEvidenceAccessAcknowledged)
                throw new InvalidOperationException("يجب الموافقة على إشعار الاحتفاظ بالنسخ قبل تعديل الدليل.");
            using var content = new MemoryStream(bytes, writable: false);
            clean.Content = content;
            return await Core(scope.ServiceProvider, db).UploadRevisionAsync(clean, reporterId);
        }
        finally
        {
            UploadBulkhead.Release();
        }
    }

    private async Task<CasePath> RequireOwnedCaseAsync(IServiceProvider services, AccpDbContext db, Guid caseId, Guid reporterId)
        => await OwnedCasePathAsync(services, db, caseId, reporterId) ?? throw DeniedException();

    private async Task<CasePath?> OwnedCasePathAsync(IServiceProvider services, AccpDbContext db, Guid caseId, Guid reporterId)
    {
        var decision = await _authorization.CheckAsync(caseId, CasePermission.ReadDetails);
        if (reporterId != Guid.Empty && decision.IsAllowed && decision.Actor is not null &&
            decision.Actor.UserId == reporterId && decision.Actor.HasRole("USER"))
        {
            // A USER+OFFICER account must still own the case to upload or disclose.
            var path = await db.CyberCases.AsNoTracking()
                .Where(item => item.Id == caseId && item.ReporterId == reporterId)
                .Select(item => (CasePath?)item.Path).FirstOrDefaultAsync();
            if (path is not null) return path;
        }
        await DeniedAsync(services, decision.Actor, caseId, null, "المستخدم لا يملك صلاحية تنفيذ عملية المرفقات على هذا الطلب.");
        return null;
    }

    private async Task<Guid?> OwnedEvidenceCaseAsync(IServiceProvider services, AccpDbContext db, Guid evidenceId, Guid reporterId)
    {
        var actor = await _authorization.GetCurrentActorAsync();
        if (evidenceId != Guid.Empty && reporterId != Guid.Empty && actor is not null &&
            actor.UserId == reporterId && actor.HasRole("USER"))
        {
            var caseId = await db.EvidenceItems.AsNoTracking()
                .Where(item => item.Id == evidenceId && item.CyberCase.ReporterId == reporterId)
                .Select(item => (Guid?)item.CyberCaseId).FirstOrDefaultAsync();
            if (caseId is not null) return caseId;
        }
        await DeniedAsync(services, actor, null, evidenceId, "المرفق غير متاح لهذا الحساب أو لا يملك المستخدم صلاحية تعديله.");
        return null;
    }

    private static EvidenceService Core(IServiceProvider services, AccpDbContext db)
        => new(
            db,
            services.GetRequiredService<IHostEnvironment>(),
            services.GetRequiredService<IAuditService>(),
            services.GetService<IDataEncryptionService>(),
            services.GetService<IEvidenceMalwareScanner>());

    private static Task<AuditLog> DeniedAsync(IServiceProvider services, CaseAccessActor? actor,
        Guid? caseId, Guid? evidenceId, string reason)
        => services.GetRequiredService<IAuditService>().WriteAsync(new AuditLogRequest
        {
            Action = AuditAction.AccessDenied,
            ActorUserId = actor?.UserId,
            ActorRole = actor is null ? "UNKNOWN" : actor.HasRole("USER") ? "USER"
                : actor.HasRole("OFFICER") ? "OFFICER" : actor.HasRole("ADMIN") ? "ADMIN" : "UNKNOWN",
            CyberCaseId = caseId is { } id && id != Guid.Empty ? id : null,
            EntityType = nameof(Evidence),
            EntityId = evidenceId is { } itemId && itemId != Guid.Empty ? itemId : null,
            Description = "تم رفض عملية مرفقات بسبب صلاحيات الوصول.",
            IsSuccessful = false, FailureReason = reason
        });

    private static UnauthorizedAccessException DeniedException()
        => new("لا تملك صلاحية تنفيذ هذه العملية. تحقق من تسجيل الدخول وملكية الطلب.");

    private static async Task<byte[]> ReadBoundedAsync(Stream content, long expectedSize)
    {
        if (content is null || !content.CanRead || expectedSize <= 0 || expectedSize > MaximumFileSize)
            throw new InvalidOperationException("الملف غير قابل للقراءة أو حجمه غير صالح. الحد الأقصى 10 ميغابايت.");
        using var buffer = new MemoryStream();
        var block = new byte[81920];
        while (true)
        {
            var count = await content.ReadAsync(block.AsMemory());
            if (count == 0) break;
            if (buffer.Length + count > expectedSize || buffer.Length + count > MaximumFileSize)
                throw new InvalidOperationException("حجم الملف الفعلي يتجاوز الحجم المسموح أو المعلن.");
            await buffer.WriteAsync(block.AsMemory(0, count));
        }
        if (buffer.Length != expectedSize)
            throw new InvalidOperationException("حجم الملف الفعلي لا يطابق الحجم المرسل.");
        return buffer.ToArray();
    }
}