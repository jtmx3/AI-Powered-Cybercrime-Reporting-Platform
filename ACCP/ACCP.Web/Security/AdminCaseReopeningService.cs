using ACCP.Application.Cases;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using ACCP.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ACCP.Web.Security;

public sealed record ReopeningOfficer(Guid Id, string FullName, string Email);
public sealed record ReopeningPage(IReadOnlyList<CaseReopeningSnapshot> Items, bool HasMore);

public sealed class AdminCaseReopeningService(
    CaseAuthorizationService authorization,
    IServiceScopeFactory scopeFactory)
{
    public async Task<ReopeningPage> GetCasesAsync(
        int page, string? caseNumber, CancellationToken cancellationToken = default)
    {
        await RequireAdminAsync(cancellationToken);
        if (page is < 0 or > 100000) throw new ArgumentOutOfRangeException(nameof(page));
        string search = caseNumber?.Trim() ?? string.Empty;
        if (search.Length > 200) throw new ArgumentException("رقم القضية طويل جدًا.");
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var query = db.CyberCases.AsNoTracking().Where(item =>
            item.Path == CasePath.FormalReport &&
            (item.Status == CaseStatus.Resolved || item.Status == CaseStatus.Closed));
        if (search.Length > 0) query = query.Where(item => item.CaseNumber == search);
        var rows = await query.OrderByDescending(item => item.CreatedAtUtc).ThenBy(item => item.Id)
            .Skip(page * 20).Take(21)
            .Select(item => new { item.Id, item.CaseNumber, item.Status,
                item.AssignedOfficerId, item.AssignedAtUtc,
                HistoryCount = db.CaseStatusHistories.Count(history => history.CyberCaseId == item.Id) })
            .ToListAsync(cancellationToken);
        return new(rows.Take(20).Select(item => new CaseReopeningSnapshot(
            item.Id, item.CaseNumber, item.Status, item.AssignedOfficerId, item.AssignedAtUtc, item.HistoryCount))
            .ToList(), rows.Count > 20);
    }

    public async Task<IReadOnlyList<ReopeningOfficer>> GetOfficersAsync(
        CancellationToken cancellationToken = default)
    {
        await RequireAdminAsync(cancellationToken);
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var members = db.UserRoles.Join(db.Roles, member => member.RoleId,
            role => role.Id, (member, role) => new { member.UserId, role.Name });
        var officers = members.Where(item => item.Name == IdentityRoles.Officer).Select(item => item.UserId);
        var admins = members.Where(item => item.Name == IdentityRoles.Admin).Select(item => item.UserId);
        var now = DateTimeOffset.UtcNow;
        var rows = await db.Users.AsNoTracking().Where(user => user.IsActive &&
                officers.Contains(user.Id) && !admins.Contains(user.Id) && user.Email != null &&
                (!user.LockoutEnabled || user.LockoutEnd == null || user.LockoutEnd <= now))
            .OrderBy(user => user.FullName).ThenBy(user => user.Id)
            .Select(user => new { user.Id, user.FullName, user.Email })
            .ToListAsync(cancellationToken);
        return rows.Select(user => new ReopeningOfficer(user.Id, user.FullName, user.Email!)).ToList();
    }

    public async Task<bool> ReopenAsync(CaseReopeningSnapshot expected,
        Guid targetOfficerId, string reason)
    {
        var adminId = await RequireAdminAsync(CancellationToken.None);
        await using var scope = scopeFactory.CreateAsyncScope();
        var service = ActivatorUtilities.CreateInstance<CaseReopeningService>(scope.ServiceProvider);
        // Do not cancel a submitted write merely because the page is closed.
        return await service.ReopenAsync(expected, targetOfficerId, adminId, reason);
    }

    private async Task<Guid> RequireAdminAsync(CancellationToken cancellationToken)
    {
        // Current actor checks active account, current role, security stamp and MFA.
        var actor = await authorization.GetCurrentActorAsync(cancellationToken);
        if (actor is null || !actor.IsAuthenticated || !actor.IsActive ||
            actor.UserId == Guid.Empty || !actor.HasRole(IdentityRoles.Admin))
            throw new UnauthorizedAccessException("إعادة الفتح متاحة لمدير فعّال أكمل التحقق الثنائي فقط.");
        return actor.UserId;
    }
}
