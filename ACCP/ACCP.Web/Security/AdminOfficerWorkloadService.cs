using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ACCP.Web.Security;

public sealed record OfficerWorkloadSummary(
    Guid OfficerId,
    string FullName,
    string Email,
    bool IsActive,
    bool HasAdminRole,
    int OpenCaseCount);

public sealed record OfficerOpenCaseSummary(
    Guid CaseId,
    string CaseNumber,
    CaseStatus Status,
    DateTime CreatedAtUtc,
    DateTime? AssignedAtUtc);

public sealed record OfficerOpenCasesPage(
    IReadOnlyList<OfficerOpenCaseSummary> Items,
    bool HasMore);

public sealed class AdminOfficerWorkloadService
{
    private readonly CaseAuthorizationService _authorization;
    private readonly IServiceScopeFactory _scopeFactory;

    public AdminOfficerWorkloadService(
        CaseAuthorizationService authorization,
        IServiceScopeFactory scopeFactory)
    {
        _authorization = authorization;
        _scopeFactory = scopeFactory;
    }

    public async Task<IReadOnlyList<OfficerWorkloadSummary>>
        GetOfficersAsync(
            CancellationToken cancellationToken = default)
    {
        await RequireAdminAsync(cancellationToken);

        await using var scope = _scopeFactory.CreateAsyncScope();

        var db = scope.ServiceProvider
            .GetRequiredService<AccpDbContext>();

        var officerIds = db.UserRoles
            .Join(
                db.Roles,
                membership => membership.RoleId,
                role => role.Id,
                (membership, role) => new
                {
                    membership.UserId,
                    role.Name
                })
            .Where(item => item.Name == IdentityRoles.Officer)
            .Select(item => item.UserId);

        var adminIds = db.UserRoles
            .Join(
                db.Roles,
                membership => membership.RoleId,
                role => role.Id,
                (membership, role) => new
                {
                    membership.UserId,
                    role.Name
                })
            .Where(item => item.Name == IdentityRoles.Admin)
            .Select(item => item.UserId);

        return await db.Users
            .AsNoTracking()
            .Where(user => officerIds.Contains(user.Id))
            .Select(user => new
            {
                user.Id,
                user.FullName,
                Email = user.Email ?? string.Empty,
                user.IsActive,
                HasAdminRole = adminIds.Contains(user.Id),
                OpenCaseCount = db.CyberCases.Count(item =>
                    item.Path == CasePath.FormalReport &&
                    item.AssignedOfficerId == user.Id &&
                    item.Status != CaseStatus.Resolved &&
                    item.Status != CaseStatus.Closed)
            })
            .OrderByDescending(item => item.OpenCaseCount)
            .ThenBy(item => item.Id)
            .Select(item => new OfficerWorkloadSummary(
                item.Id,
                item.FullName,
                item.Email,
                item.IsActive,
                item.HasAdminRole,
                item.OpenCaseCount))
            .ToListAsync(cancellationToken);
    }

    public async Task<OfficerOpenCasesPage> GetOpenCasesAsync(
        Guid officerId,
        int skip = 0,
        int take = 20,
        CancellationToken cancellationToken = default)
    {
        await RequireAdminAsync(cancellationToken);

        if (officerId == Guid.Empty)
        {
            throw new ArgumentException(
                "اختر موظفًا صالحًا.",
                nameof(officerId));
        }

        if (skip < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(skip));
        }

        var pageSize = Math.Clamp(take, 1, 100);

        await using var scope = _scopeFactory.CreateAsyncScope();

        var db = scope.ServiceProvider
            .GetRequiredService<AccpDbContext>();

        var rows = await db.CyberCases
            .AsNoTracking()
            .Where(item =>
                item.Path == CasePath.FormalReport &&
                item.AssignedOfficerId == officerId &&
                item.Status != CaseStatus.Resolved &&
                item.Status != CaseStatus.Closed)
            .OrderBy(item => item.AssignedAtUtc)
            .ThenBy(item => item.Id)
            .Skip(skip)
            .Take(pageSize + 1)
            .Select(item => new OfficerOpenCaseSummary(
                item.Id,
                item.CaseNumber,
                item.Status,
                item.CreatedAtUtc,
                item.AssignedAtUtc))
            .ToListAsync(cancellationToken);

        return new OfficerOpenCasesPage(
            rows.Take(pageSize).ToArray(),
            rows.Count > pageSize);
    }

    private async Task RequireAdminAsync(
        CancellationToken cancellationToken)
    {
        var actor = await _authorization.GetCurrentActorAsync(
            cancellationToken);

        if (actor is null ||
            !actor.IsAuthenticated ||
            !actor.IsActive ||
            actor.UserId == Guid.Empty ||
            !actor.HasRole(IdentityRoles.Admin))
        {
            throw new UnauthorizedAccessException(
                "متابعة توزيع القضايا متاحة لمدير فعّال " +
                "أكمل التحقق الثنائي فقط.");
        }
    }
}