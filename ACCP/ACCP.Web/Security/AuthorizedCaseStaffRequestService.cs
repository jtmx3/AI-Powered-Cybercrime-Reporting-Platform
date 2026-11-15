using ACCP.Application.CaseStaffing;
using ACCP.Application.Security;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using ACCP.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ACCP.Web.Security;

public sealed class AuthorizedCaseStaffRequestService
    : ICaseStaffRequestService
{
    private readonly CaseAuthorizationService _authorization;
    private readonly IServiceScopeFactory _scopeFactory;

    public AuthorizedCaseStaffRequestService(
        CaseAuthorizationService authorization,
        IServiceScopeFactory scopeFactory)
    {
        _authorization = authorization;
        _scopeFactory = scopeFactory;
    }

    public Task<CaseStaffRequest?> CreateForOfficerAsync(
        Guid cyberCaseId,
        CaseStaffRequestType requestType,
        string reason,
        Guid officerId,
        string officerEmail) =>
        ExecuteAsync<CaseStaffRequest?>(
            IdentityRoles.Officer,
            officerId,
            async (service, actor, email) =>
            {
                var decision = await _authorization.CheckAsync(
                    cyberCaseId,
                    CasePermission.ManageStaffing);

                if (!decision.IsAllowed ||
                    decision.Actor?.UserId != actor.UserId)
                {
                    throw AccessDenied();
                }

                return await service.CreateForOfficerAsync(
                    cyberCaseId,
                    requestType,
                    reason,
                    actor.UserId,
                    email);
            });

    public Task<List<CaseStaffRequest>> GetForOfficerAsync(
        Guid officerId) =>
        ExecuteAsync<List<CaseStaffRequest>>(
            IdentityRoles.Officer,
            officerId,
            (service, actor, _) =>
                service.GetForOfficerAsync(actor.UserId));

    public async Task<List<CaseStaffRequest>> GetForAdminAsync(
        CaseStaffRequestStatus? status = null)
    {
        await RequireAdminAsync();

        if (status.HasValue && !Enum.IsDefined(status.Value))
            throw new ArgumentOutOfRangeException(nameof(status));

        await using var scope = _scopeFactory.CreateAsyncScope();

        var db = scope.ServiceProvider
            .GetRequiredService<AccpDbContext>();

        var query = AdminReadQuery(db);

        if (status.HasValue)
            query = query.Where(item => item.Status == status.Value);

        return await query
            .OrderByDescending(item => item.CreatedAtUtc)
            .ThenBy(item => item.Id)
            .ToListAsync();
    }

    public async Task<CaseStaffRequest?> GetByIdForAdminAsync(
        Guid requestId)
    {
        await RequireAdminAsync();

        if (requestId == Guid.Empty)
            return null;

        await using var scope = _scopeFactory.CreateAsyncScope();

        var db = scope.ServiceProvider
            .GetRequiredService<AccpDbContext>();

        return await AdminReadQuery(db)
            .FirstOrDefaultAsync(item => item.Id == requestId);
    }

    // لا نحمل كائن القضية كاملًا.
    // الحقول غير المحددة هنا لا تُقرأ من قاعدة البيانات.
    private static IQueryable<CaseStaffRequest> AdminReadQuery(
        AccpDbContext db) =>
        db.CaseStaffRequests
            .AsNoTracking()
            .Where(item =>
                item.CyberCase.Path == CasePath.FormalReport)
            .Select(item => new CaseStaffRequest
            {
                Id = item.Id,
                CyberCaseId = item.CyberCaseId,

                CyberCase = new CyberCase
                {
                    Id = item.CyberCaseId,
                    CaseNumber = item.CyberCase.CaseNumber,
                    AssignedOfficerId =
                        item.CyberCase.AssignedOfficerId,
                    Path = item.CyberCase.Path
                },

                RequestedByOfficerId = item.RequestedByOfficerId,
                RequestedByOfficerEmail = item.RequestedByOfficerEmail,
                RequestType = item.RequestType,
                Reason = item.Reason,
                Status = item.Status,
                TargetOfficerId = item.TargetOfficerId,
                TargetOfficerEmail = item.TargetOfficerEmail,
                ReviewedByAdminId = item.ReviewedByAdminId,
                ReviewedByAdminEmail = item.ReviewedByAdminEmail,
                DecisionNote = item.DecisionNote,
                CreatedAtUtc = item.CreatedAtUtc,
                ReviewedAtUtc = item.ReviewedAtUtc,
                RowVersion = item.RowVersion
            });

    public Task<bool> ApproveForAdminAsync(
        Guid requestId,
        Guid targetOfficerId,
        Guid adminId,
        string adminEmail,
        string? decisionNote) =>
        ExecuteAsync<bool>(
            IdentityRoles.Admin,
            adminId,
            (service, actor, email) =>
                service.ApproveForAdminAsync(
                    requestId,
                    targetOfficerId,
                    actor.UserId,
                    email,
                    decisionNote));

    public Task<bool> RejectForAdminAsync(
        Guid requestId,
        Guid adminId,
        string adminEmail,
        string decisionNote) =>
        ExecuteAsync<bool>(
            IdentityRoles.Admin,
            adminId,
            (service, actor, email) =>
                service.RejectForAdminAsync(
                    requestId,
                    actor.UserId,
                    email,
                    decisionNote));

    public Task<bool> CancelForOfficerAsync(
        Guid requestId,
        Guid officerId,
        string officerEmail) =>
        ExecuteAsync<bool>(
            IdentityRoles.Officer,
            officerId,
            (service, actor, email) =>
                service.CancelForOfficerAsync(
                    requestId,
                    actor.UserId,
                    email));

    private async Task RequireAdminAsync()
    {
        var actor = await _authorization.GetCurrentActorAsync();

        if (actor is null ||
            !actor.IsAuthenticated ||
            !actor.IsActive ||
            actor.UserId == Guid.Empty ||
            !actor.HasRole(IdentityRoles.Admin))
        {
            throw AccessDenied();
        }
    }

    private async Task<T> ExecuteAsync<T>(
        string requiredRole,
        Guid? expectedActorId,
        Func<CaseStaffRequestService, CaseAccessActor, string, Task<T>>
            operation)
    {
        var actor = await _authorization.GetCurrentActorAsync();

        if (actor is null ||
            !actor.IsAuthenticated ||
            !actor.IsActive ||
            actor.UserId == Guid.Empty ||
            !actor.HasRole(requiredRole) ||
            (expectedActorId.HasValue &&
             expectedActorId.Value != actor.UserId))
        {
            throw AccessDenied();
        }

        await using var scope = _scopeFactory.CreateAsyncScope();

        var db = scope.ServiceProvider
            .GetRequiredService<AccpDbContext>();

        var email = await db.Users
            .AsNoTracking()
            .Where(user =>
                user.Id == actor.UserId && user.IsActive)
            .Select(user => user.Email)
            .SingleOrDefaultAsync();

        if (string.IsNullOrWhiteSpace(email))
            throw AccessDenied();

        var service =
            ActivatorUtilities.CreateInstance<CaseStaffRequestService>(
                scope.ServiceProvider);

        return await operation(service, actor, email.Trim());
    }

    private static UnauthorizedAccessException AccessDenied() =>
        new(
            "لا تملك صلاحية تنفيذ هذا الإجراء، " +
            "أو انتهت صلاحية جلستك. سجّل الدخول مجددًا.");
}