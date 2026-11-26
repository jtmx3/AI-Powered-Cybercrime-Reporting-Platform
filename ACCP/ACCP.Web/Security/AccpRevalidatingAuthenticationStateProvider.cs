using System.Security.Claims;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ACCP.Web.Security;

/// <summary>
/// Periodically revalidates active Blazor InteractiveServer circuits against the database
/// so deactivated, locked-out, role-changed, or MFA-revoked sessions are terminated promptly.
/// </summary>
public sealed class AccpRevalidatingAuthenticationStateProvider
    : RevalidatingServerAuthenticationStateProvider
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IdentityOptions _identityOptions;

    public AccpRevalidatingAuthenticationStateProvider(
        ILoggerFactory loggerFactory,
        IServiceScopeFactory scopeFactory,
        IOptions<IdentityOptions> identityOptions)
        : base(loggerFactory)
    {
        _scopeFactory = scopeFactory;
        _identityOptions = identityOptions.Value;
    }

    protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(2);

    protected override async Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authenticationState,
        CancellationToken cancellationToken)
    {
        var principal = authenticationState.User;
        if (principal.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        if (!Guid.TryParse(
                principal.FindFirstValue(_identityOptions.ClaimsIdentity.UserIdClaimType),
                out var userId) ||
            userId == Guid.Empty)
        {
            return false;
        }

        var sessionStamp = principal.FindFirstValue(
            _identityOptions.ClaimsIdentity.SecurityStampClaimType);

        if (string.IsNullOrWhiteSpace(sessionStamp))
        {
            return false;
        }

        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();

        var user = await db.Users
            .AsNoTracking()
            .Where(item => item.Id == userId)
            .Select(item => new
            {
                item.Id,
                item.IsActive,
                item.SecurityStamp,
                item.TwoFactorEnabled,
                item.LockoutEnabled,
                item.LockoutEnd
            })
            .FirstOrDefaultAsync(cancellationToken);

        if (user is null ||
            !user.IsActive ||
            string.IsNullOrWhiteSpace(user.SecurityStamp) ||
            !string.Equals(user.SecurityStamp, sessionStamp, StringComparison.Ordinal) ||
            (user.LockoutEnabled && user.LockoutEnd is { } end && end > DateTimeOffset.UtcNow))
        {
            return false;
        }

        var isStaff = await db.UserRoles
            .Where(membership => membership.UserId == user.Id)
            .Join(
                db.Roles,
                membership => membership.RoleId,
                role => role.Id,
                (_, role) => role.NormalizedName)
            .AnyAsync(
                role => role == IdentityRoles.Officer || role == IdentityRoles.Admin,
                cancellationToken);

        if (isStaff && (!user.TwoFactorEnabled || !StaffTwoFactorFlow.HasCompletedTwoFactor(principal)))
        {
            return false;
        }

        return true;
    }
}
