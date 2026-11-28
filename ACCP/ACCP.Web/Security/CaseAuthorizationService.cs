using System.Security.Claims;
using ACCP.Application.Security;
using ACCP.Domain.Entities;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace ACCP.Web.Security;

/// <summary>
/// Server-owned result of a current access check, not a token or browser input.
/// Recheck for every operation; do not cache an allowed result in the page.
/// </summary>
public sealed record CaseAuthorizationDecision(
    CaseAccessActor? Actor,
    bool IsAllowed);

/// <summary>
/// Resolves the server-authenticated identity and reloads account status, roles,
/// and case relationships before evaluating CaseAccessPolicy.
/// Registration and calls from case/evidence services are added separately.
/// </summary>
public sealed class CaseAuthorizationService
{
    private readonly AuthenticationStateProvider _authenticationStateProvider;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IdentityOptions _identityOptions;
    private readonly IWebHostEnvironment _environment;

    public CaseAuthorizationService(
        AuthenticationStateProvider authenticationStateProvider,
        IHttpContextAccessor httpContextAccessor,
        IServiceScopeFactory scopeFactory,
        IOptions<IdentityOptions> identityOptions,
        IWebHostEnvironment environment)
    {
        _authenticationStateProvider = authenticationStateProvider;
        _httpContextAccessor = httpContextAccessor;
        _scopeFactory = scopeFactory;
        _identityOptions = identityOptions.Value;
        _environment = environment;
    }

    public async Task<CaseAccessActor?> GetCurrentActorAsync(
        CancellationToken cancellationToken = default)
    {
        var principal = await GetCurrentPrincipalAsync(cancellationToken);
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        return await ReadActorAsync(principal, db, cancellationToken);
    }

    public async Task<CaseAuthorizationDecision> CheckAsync(
        Guid caseId,
        CasePermission permission,
        CancellationToken cancellationToken = default)
    {
        if (caseId == Guid.Empty || !Enum.IsDefined(permission))
            return new(null, false);

        var principal = await GetCurrentPrincipalAsync(cancellationToken);
        // A separate scope avoids concurrent access to a circuit's shared DbContext.
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var actor = await ReadActorAsync(principal, db, cancellationToken);
        if (actor is null)
            return new(null, false);

        // Load only the fields needed for authorization, not complaint text or files.
        var snapshot = await db.CyberCases
            .AsNoTracking()
            .Where(item => item.Id == caseId)
            .Select(item => new CyberCase
            {
                Id = item.Id,
                ReporterId = item.ReporterId,
                Path = item.Path,
                Status = item.Status,
                AssignedOfficerId = item.AssignedOfficerId,
                IsReporterIdentityDisclosed = item.IsReporterIdentityDisclosed,
                Collaborators = item.Collaborators
                    .Where(collaborator => collaborator.IsActive)
                    .Select(collaborator => new CaseCollaborator
                    {
                        CyberCaseId = collaborator.CyberCaseId,
                        OfficerId = collaborator.OfficerId,
                        IsActive = collaborator.IsActive
                    }).ToList()
            })
            .FirstOrDefaultAsync(cancellationToken);

        // Supervisor team scope is not implemented yet: it remains denied by default.
        return new(actor, CaseAccessPolicy.IsAllowed(actor, snapshot, permission));
    }

    private async Task<ClaimsPrincipal> GetCurrentPrincipalAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            var state = await _authenticationStateProvider
                .GetAuthenticationStateAsync()
                .WaitAsync(cancellationToken);
            return state.User;
        }
        catch (InvalidOperationException) when (_httpContextAccessor.HttpContext is not null)
        {
            // Outside a Blazor component/circuit, the request's authentication
            // middleware supplies HttpContext.User. Never accept a principal from a form.
            return _httpContextAccessor.HttpContext.User;
        }
    }

    private async Task<CaseAccessActor?> ReadActorAsync(
        ClaimsPrincipal principal,
        AccpDbContext db,
        CancellationToken cancellationToken)
    {
        if (principal.Identity?.IsAuthenticated != true ||
            !Guid.TryParse(principal.FindFirstValue(
                _identityOptions.ClaimsIdentity.UserIdClaimType), out var userId) ||
            userId == Guid.Empty)
        {
            return null;
        }

        var account = await db.Users
            .AsNoTracking()
            .Where(user => user.Id == userId)
            .Select(user => new { user.Id, user.Email, user.IsActive, user.SecurityStamp, user.TwoFactorEnabled, user.LockoutEnabled, user.LockoutEnd })
            .FirstOrDefaultAsync(cancellationToken);

        var sessionStamp = principal.FindFirstValue(
            _identityOptions.ClaimsIdentity.SecurityStampClaimType);
        if (account is null || !account.IsActive ||
            (account.LockoutEnabled && account.LockoutEnd is { } lockout && lockout > DateTimeOffset.UtcNow) ||
            string.IsNullOrWhiteSpace(account.SecurityStamp) ||
            string.IsNullOrWhiteSpace(sessionStamp) ||
            !string.Equals(account.SecurityStamp, sessionStamp, StringComparison.Ordinal))
        {
            return null;
        }

        // Read current database roles; cookie role claims may have become stale.
        var roles = await db.UserRoles
            .Where(userRole => userRole.UserId == userId)
            .Join(db.Roles,
                userRole => userRole.RoleId,
                role => role.Id,
                (_, role) => role.Name)
            .Where(name => name != null)
            .Select(name => name!)
            .ToListAsync(cancellationToken);

        // A Blazor circuit can outlive its HTTP request. The exemption claim is
        // signed at localhost login, time-limited, and revalidated per operation.
        var isOfficer = roles.Contains(IdentityRoles.Officer);
        var isAdmin = roles.Contains(IdentityRoles.Admin);
        var currentHttpContext = _httpContextAccessor.HttpContext;
        var localExemption =
            LocalDevelopmentMfaExemption.HasValidPrincipalClaim(
                principal,
                _environment,
                account.Email,
                isAdmin && !isOfficer) &&
            (currentHttpContext is null ||
             LocalDevelopmentMfaExemption.IsLoopbackRequest(
                 currentHttpContext));

        if ((isOfficer || isAdmin) &&
            !localExemption &&
            (!account.TwoFactorEnabled ||
             !HasOfficerMfa(principal, account.Id, sessionStamp)))
        {
            return null;
        }

        return new CaseAccessActor(account.Id, true, true, roles);
    }

    private bool HasOfficerMfa(ClaimsPrincipal principal, Guid accountId, string securityStamp) =>
        principal.Identities.Any(identity => identity.IsAuthenticated &&
            identity.AuthenticationType == IdentityConstants.ApplicationScheme &&
            identity.HasClaim("amr", "mfa") &&
            Guid.TryParse(identity.FindFirst(_identityOptions.ClaimsIdentity.UserIdClaimType)?.Value,
                out var identityAccountId) && identityAccountId == accountId &&
            string.Equals(identity.FindFirst(_identityOptions.ClaimsIdentity.SecurityStampClaimType)?.Value,
                securityStamp, StringComparison.Ordinal));
}
