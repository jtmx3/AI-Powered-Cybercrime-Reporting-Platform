using System.Security.Claims;
using ACCP.Application.Auditing;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ACCP.Web.Pages.Account;

[Authorize]
public class LogoutModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IAuditService _auditService;

    public LogoutModel(
        SignInManager<ApplicationUser> signInManager,
        IAuditService auditService)
    {
        _signInManager = signInManager;
        _auditService = auditService;
    }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        string? userIdValue =
            User.FindFirstValue(
                ClaimTypes.NameIdentifier);

        Guid? actorUserId =
            Guid.TryParse(
                userIdValue,
                out Guid parsedUserId)
                ? parsedUserId
                : null;

        string? actorEmail =
            User.FindFirstValue(
                ClaimTypes.Email)
            ?? User.Identity?.Name;

        string actorRole = GetActorRole();

        string? ipAddress =
            HttpContext.Connection
                .RemoteIpAddress
                ?.ToString();

        string userAgent =
            Request.Headers[
                "User-Agent"].ToString();

        string correlationId =
            HttpContext.TraceIdentifier;

        await _signInManager.SignOutAsync();

        await _auditService.WriteAsync(
            new AuditLogRequest
            {
                Action = AuditAction.UserLoggedOut,
                ActorUserId = actorUserId,
                ActorEmail = actorEmail,
                ActorRole = actorRole,
                EntityType = nameof(ApplicationUser),
                EntityId = actorUserId,
                Description =
                    "تم تسجيل الخروج بنجاح.",
                IsSuccessful = true,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                CorrelationId = correlationId
            });

        return LocalRedirect("/login");
    }

    private string GetActorRole()
    {
        if (User.IsInRole(IdentityRoles.Admin))
        {
            return IdentityRoles.Admin;
        }

        if (User.IsInRole(IdentityRoles.Officer))
        {
            return IdentityRoles.Officer;
        }

        if (User.IsInRole(IdentityRoles.User))
        {
            return IdentityRoles.User;
        }

        return "UNKNOWN";
    }
}
