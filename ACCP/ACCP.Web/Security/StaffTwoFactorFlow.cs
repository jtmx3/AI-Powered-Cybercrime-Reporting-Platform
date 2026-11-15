using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ACCP.Web.Security;

public static class StaffTwoFactorFlow
{
    private const string CookieName = "ACCP.StaffEnrollment";
    private const string Purpose =
        "ACCP.StaffEnrollment.PasswordVerified.v1";

    private static readonly TimeSpan Lifetime =
        TimeSpan.FromMinutes(10);

    public static async Task BeginEnrollmentAsync(
        HttpContext context,
        ApplicationUser passwordVerifiedUser,
        string expectedSecurityStamp)
    {
        var db = context.RequestServices
            .GetRequiredService<AccpDbContext>();

        var current = await db.Users
            .AsNoTracking()
            .SingleOrDefaultAsync(
                user => user.Id == passwordVerifiedUser.Id,
                context.RequestAborted);

        if (current is null ||
            !CanEnroll(current) ||
            string.IsNullOrWhiteSpace(expectedSecurityStamp) ||
            !string.Equals(
                current.SecurityStamp,
                expectedSecurityStamp,
                StringComparison.Ordinal) ||
            !await IsStaffAsync(
                db,
                current.Id,
                context.RequestAborted))
        {
            ClearEnrollment(context);

            throw new InvalidOperationException(
                "تغيّرت حالة الحساب. أعد تسجيل الدخول.");
        }

        var signIn = context.RequestServices
            .GetRequiredService<SignInManager<ApplicationUser>>();

        await signIn.SignOutAsync();
        await signIn.ForgetTwoFactorClientAsync();

        context.User = new ClaimsPrincipal(new ClaimsIdentity());

        DeleteCookie(context, "ACCP.PendingTwoFactor");
        DeleteCookie(context, "ACCP.TwoFactorEnrollment");

        var payload = JsonSerializer.Serialize(
            new EnrollmentTicket(
                current.Id,
                current.SecurityStamp!));

        context.Response.Cookies.Append(
            CookieName,
            Protector(context).Protect(payload, Lifetime),
            CookieOptions(context));
    }

    public static async Task<ApplicationUser?>
        GetEnrollmentUserAsync(HttpContext context)
    {
        var ticket = ReadTicket(context);

        if (ticket is null)
        {
            ClearEnrollment(context);
            return null;
        }

        var db = context.RequestServices
            .GetRequiredService<AccpDbContext>();

        var users = context.RequestServices
            .GetRequiredService<UserManager<ApplicationUser>>();

        var user = await users.FindByIdAsync(
            ticket.UserId.ToString());

        if (user is not null)
        {
            await db.Entry(user)
                .ReloadAsync(context.RequestAborted);
        }

        if (user is null ||
            db.Entry(user).State == EntityState.Detached ||
            !CanEnroll(user) ||
            !string.Equals(
                user.SecurityStamp,
                ticket.SecurityStamp,
                StringComparison.Ordinal) ||
            !await IsStaffAsync(
                db,
                user.Id,
                context.RequestAborted))
        {
            ClearEnrollment(context);
            return null;
        }

        return user;
    }

    public static void ClearEnrollment(HttpContext context) =>
        DeleteCookie(context, CookieName);

    public static bool HasCompletedTwoFactor(
        ClaimsPrincipal principal) =>
        principal.Identities.Any(identity =>
            identity.IsAuthenticated &&
            identity.AuthenticationType ==
                IdentityConstants.ApplicationScheme &&
            identity.HasClaim("amr", "mfa"));

    public static IApplicationBuilder UseRequiredOfficerTwoFactor(
        this IApplicationBuilder app)
    {
        return app.Use(async (context, next) =>
        {
            if (context.User.Identity?.IsAuthenticated == true &&
                !await IsApplicationSessionAllowedAsync(context))
            {
                var signIn = context.RequestServices
                    .GetRequiredService<
                        SignInManager<ApplicationUser>>();

                await signIn.SignOutAsync();
                await signIn.ForgetTwoFactorClientAsync();

                context.User =
                    new ClaimsPrincipal(new ClaimsIdentity());

                ClearEnrollment(context);
            }

            await next(context);
        });
    }

    private static async Task<bool>
        IsApplicationSessionAllowedAsync(HttpContext context)
    {
        var users = context.RequestServices
            .GetRequiredService<UserManager<ApplicationUser>>();

        var options = users.Options.ClaimsIdentity;

        if (!Guid.TryParse(
                context.User.FindFirstValue(
                    options.UserIdClaimType),
                out var id))
        {
            return false;
        }

        var stamp = context.User.FindFirstValue(
            options.SecurityStampClaimType);

        var db = context.RequestServices
            .GetRequiredService<AccpDbContext>();

        var user = await db.Users
            .AsNoTracking()
            .SingleOrDefaultAsync(
                item => item.Id == id,
                context.RequestAborted);

        if (user is null ||
            !user.IsActive ||
            string.IsNullOrWhiteSpace(stamp) ||
            string.IsNullOrWhiteSpace(user.SecurityStamp) ||
            !string.Equals(
                user.SecurityStamp,
                stamp,
                StringComparison.Ordinal) ||
            IsLocked(user))
        {
            return false;
        }

        if (!await IsStaffAsync(
                db,
                user.Id,
                context.RequestAborted))
        {
            return true;
        }

        return user.TwoFactorEnabled &&
            HasCompletedTwoFactor(context.User);
    }

    private static bool CanEnroll(ApplicationUser user) =>
        user.IsActive &&
        !user.TwoFactorEnabled &&
        !string.IsNullOrWhiteSpace(user.SecurityStamp) &&
        !IsLocked(user);

    private static bool IsLocked(ApplicationUser user) =>
        user.LockoutEnabled &&
        user.LockoutEnd is { } end &&
        end > DateTimeOffset.UtcNow;

    private static Task<bool> IsStaffAsync(
        AccpDbContext db,
        Guid id,
        CancellationToken cancellationToken) =>
        db.UserRoles
            .Where(membership => membership.UserId == id)
            .Join(
                db.Roles,
                membership => membership.RoleId,
                role => role.Id,
                (_, role) => role.NormalizedName)
            .AnyAsync(
                role =>
                    role == IdentityRoles.Officer ||
                    role == IdentityRoles.Admin,
                cancellationToken);

    private static EnrollmentTicket? ReadTicket(
        HttpContext context)
    {
        if (!context.Request.Cookies.TryGetValue(
                CookieName,
                out var value) ||
            string.IsNullOrWhiteSpace(value) ||
            value.Length > 4096)
        {
            return null;
        }

        try
        {
            var ticket =
                JsonSerializer.Deserialize<EnrollmentTicket>(
                    Protector(context).Unprotect(value));

            return ticket is not null &&
                ticket.UserId != Guid.Empty &&
                !string.IsNullOrWhiteSpace(ticket.SecurityStamp)
                    ? ticket
                    : null;
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static ITimeLimitedDataProtector Protector(
        HttpContext context) =>
        context.RequestServices
            .GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(Purpose)
            .ToTimeLimitedDataProtector();

    private static CookieOptions CookieOptions(
        HttpContext context) => new()
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            SameSite = SameSiteMode.Strict,
            IsEssential = true,
            Path = "/",
            MaxAge = Lifetime
        };

    private static void DeleteCookie(
        HttpContext context,
        string name)
    {
        var options = CookieOptions(context);
        options.MaxAge = TimeSpan.Zero;

        context.Response.Cookies.Delete(name, options);
    }

    private sealed record EnrollmentTicket(
        Guid UserId,
        string SecurityStamp);
}