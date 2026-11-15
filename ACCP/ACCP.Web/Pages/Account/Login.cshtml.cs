using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using ACCP.Application.Auditing;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using ACCP.Web.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace ACCP.Web.Pages.Account;

[AllowAnonymous]
[ResponseCache(
    Duration = 0,
    Location = ResponseCacheLocation.None,
    NoStore = true)]
[RequestSizeLimit(16 * 1024)]
public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditService _auditService;
    private readonly AccpDbContext _db;

    public LoginModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IAuditService auditService,
        AccpDbContext db)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditService = auditService;
        _db = db;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string ReturnUrl { get; set; } = string.Empty;

    public void OnGet(string? returnUrl = null)
    {
        ReturnUrl = GetSafeReturnUrl(returnUrl);
        SetResponseHeaders();
    }

    public async Task<IActionResult> OnPostAsync(
        string? returnUrl = null)
    {
        ReturnUrl = GetSafeReturnUrl(returnUrl);
        SetResponseHeaders();

        await _signInManager.SignOutAsync();

        HttpContext.User =
            new ClaimsPrincipal(new ClaimsIdentity());

        await ClearPendingLoginAsync();
        StaffTwoFactorFlow.ClearEnrollment(HttpContext);

        Response.Cookies.Delete(
            "ACCP.TwoFactorEnrollment",
            new CookieOptions
            {
                Path = "/",
                HttpOnly = true,
                Secure = Request.IsHttps,
                SameSite = SameSiteMode.Strict
            });

        if (!ModelState.IsValid)
        {
            return LoginPage();
        }

        var attemptedEmail = Input.Email.Trim();

        var user = await _userManager.FindByEmailAsync(
            attemptedEmail);

        if (user is null)
        {
            await WriteLoginAuditAsync(
                AuditAction.UserLoginFailed,
                null,
                attemptedEmail,
                "UNKNOWN",
                false,
                "البريد الإلكتروني غير مسجل.");

            ModelState.AddModelError(
                string.Empty,
                "البريد الإلكتروني أو كلمة المرور غير صحيحة.");

            return LoginPage();
        }

        var actorRole = await GetUserRoleAsync(user);

        if (!user.IsActive)
        {
            await WriteLoginAuditAsync(
                AuditAction.UserLoginFailed,
                user,
                attemptedEmail,
                actorRole,
                false,
                "الحساب غير فعال.");

            ModelState.AddModelError(
                string.Empty,
                "هذا الحساب غير فعال.");

            return LoginPage();
        }

        var expectedStamp = user.SecurityStamp;
        var expectedTwoFactor = user.TwoFactorEnabled;

        var enrollmentRequired = !user.TwoFactorEnabled &&
            (await _userManager.IsInRoleAsync(
                user,
                IdentityRoles.Officer) ||
             await _userManager.IsInRoleAsync(
                user,
                IdentityRoles.Admin));

        Microsoft.AspNetCore.Identity.SignInResult result =
            enrollmentRequired
                ? await _signInManager.CheckPasswordSignInAsync(
                    user,
                    Input.Password,
                    lockoutOnFailure: true)
                : await _signInManager.PasswordSignInAsync(
                    user,
                    Input.Password,
                    Input.RememberMe,
                    lockoutOnFailure: true);

        if (result.Succeeded || result.RequiresTwoFactor)
        {
            await _db.Entry(user).ReloadAsync();

            if (_db.Entry(user).State == EntityState.Detached ||
                !user.IsActive ||
                string.IsNullOrWhiteSpace(expectedStamp) ||
                !string.Equals(
                    user.SecurityStamp,
                    expectedStamp,
                    StringComparison.Ordinal) ||
                user.TwoFactorEnabled != expectedTwoFactor ||
                (result.RequiresTwoFactor &&
                 !user.TwoFactorEnabled) ||
                (result.Succeeded &&
                 user.TwoFactorEnabled))
            {
                await _signInManager.SignOutAsync();
                await _signInManager.ForgetTwoFactorClientAsync();
                await ClearPendingLoginAsync();

                await WriteLoginAuditAsync(
                    AuditAction.UserLoginFailed,
                    user,
                    attemptedEmail,
                    await GetUserRoleAsync(user),
                    false,
                    "تغيّرت حالة الحساب أو لم يكتمل التحقق بخطوتين.");

                ModelState.AddModelError(
                    string.Empty,
                    "تغيّرت حالة الحساب أو يلزم التحقق بخطوتين. " +
                    "أعد تسجيل الدخول.");

                return LoginPage();
            }

            actorRole = await GetUserRoleAsync(user);
        }

        if (result.Succeeded)
        {
            var currentStaff =
                await _userManager.IsInRoleAsync(
                    user,
                    IdentityRoles.Officer) ||
                await _userManager.IsInRoleAsync(
                    user,
                    IdentityRoles.Admin);

            if (enrollmentRequired && !currentStaff)
            {
                return await RejectChangedEnrollmentAsync(
                    user,
                    attemptedEmail,
                    actorRole);
            }

            if (!user.TwoFactorEnabled && currentStaff)
            {
                try
                {
                    await StaffTwoFactorFlow.BeginEnrollmentAsync(
                        HttpContext,
                        user,
                        expectedStamp!);
                }
                catch (InvalidOperationException)
                {
                    return await RejectChangedEnrollmentAsync(
                        user,
                        attemptedEmail,
                        actorRole);
                }

                ClearPassword();

                return LocalRedirect("/account/two-factor");
            }

            try
            {
                await WriteLoginAuditAsync(
                    AuditAction.UserLoggedIn,
                    user,
                    attemptedEmail,
                    actorRole,
                    true);
            }
            catch
            {
                await _signInManager.SignOutAsync();

                ModelState.AddModelError(
                    string.Empty,
                    "تعذر إكمال تسجيل الدخول. حاول مجددًا.");

                return LoginPage();
            }

            ClearPassword();

            if (!string.IsNullOrWhiteSpace(ReturnUrl))
            {
                return LocalRedirect(ReturnUrl);
            }

            if (actorRole == IdentityRoles.Admin)
            {
                return LocalRedirect("/admin/employees");
            }

            if (actorRole == IdentityRoles.Officer)
            {
                return LocalRedirect("/officer/dashboard");
            }

            return LocalRedirect("/cases");
        }

        if (result.IsLockedOut)
        {
            await WriteLoginAuditAsync(
                AuditAction.UserLoginFailed,
                user,
                attemptedEmail,
                actorRole,
                false,
                "تم قفل الحساب مؤقتًا بسبب تكرار المحاولات الفاشلة.");

            ModelState.AddModelError(
                string.Empty,
                "تم إيقاف تسجيل الدخول مؤقتًا " +
                "بسبب تكرار المحاولات الخاطئة.");

            return LoginPage();
        }

        if (result.RequiresTwoFactor)
        {
            LoginTwoFactorModel.BindPendingLogin(
                HttpContext,
                user,
                Input.RememberMe);

            ClearPassword();

            return LocalRedirect(
                string.IsNullOrEmpty(ReturnUrl)
                    ? "/login/two-factor"
                    : "/login/two-factor?returnUrl=" +
                      Uri.EscapeDataString(ReturnUrl));
        }

        await WriteLoginAuditAsync(
            AuditAction.UserLoginFailed,
            user,
            attemptedEmail,
            actorRole,
            false,
            "كلمة المرور غير صحيحة.");

        ModelState.AddModelError(
            string.Empty,
            "البريد الإلكتروني أو كلمة المرور غير صحيحة.");

        return LoginPage();
    }

    private async Task<PageResult> RejectChangedEnrollmentAsync(
        ApplicationUser user,
        string attemptedEmail,
        string actorRole)
    {
        await _signInManager.SignOutAsync();
        await _signInManager.ForgetTwoFactorClientAsync();
        await ClearPendingLoginAsync();

        StaffTwoFactorFlow.ClearEnrollment(HttpContext);

        await WriteLoginAuditAsync(
            AuditAction.UserLoginFailed,
            user,
            attemptedEmail,
            actorRole,
            false,
            "تغيّرت حالة الحساب أثناء بدء تفعيل المصادقة الثنائية.");

        ModelState.AddModelError(
            string.Empty,
            "تغيّرت حالة الحساب. أعد تسجيل الدخول.");

        return LoginPage();
    }

    private PageResult LoginPage()
    {
        ClearPassword();
        return Page();
    }

    private void ClearPassword()
    {
        Input.Password = string.Empty;

        if (ModelState.TryGetValue(
                "Input.Password",
                out var entry))
        {
            entry.RawValue = null;
            entry.AttemptedValue = null;
        }
    }

    private async Task ClearPendingLoginAsync()
    {
        Response.Cookies.Delete(
            "ACCP.PendingTwoFactor",
            new CookieOptions
            {
                Path = "/",
                HttpOnly = true,
                Secure = Request.IsHttps,
                SameSite = SameSiteMode.Strict
            });

        await HttpContext.SignOutAsync(
            IdentityConstants.TwoFactorUserIdScheme);
    }

    private void SetResponseHeaders()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
    }

    private async Task<string> GetUserRoleAsync(
        ApplicationUser user)
    {
        if (await _userManager.IsInRoleAsync(
                user,
                IdentityRoles.Admin))
        {
            return IdentityRoles.Admin;
        }

        if (await _userManager.IsInRoleAsync(
                user,
                IdentityRoles.Officer))
        {
            return IdentityRoles.Officer;
        }

        return IdentityRoles.User;
    }

    private async Task WriteLoginAuditAsync(
        AuditAction action,
        ApplicationUser? user,
        string attemptedEmail,
        string actorRole,
        bool isSuccessful,
        string? failureReason = null)
    {
        var actorEmail = string.IsNullOrWhiteSpace(user?.Email)
            ? attemptedEmail
            : user.Email;

        await _auditService.WriteAsync(
            new AuditLogRequest
            {
                Action = action,
                ActorUserId = user?.Id,
                ActorEmail = actorEmail,
                ActorRole = actorRole,
                EntityType = nameof(ApplicationUser),
                EntityId = user?.Id,
                Description = isSuccessful
                    ? "تم تسجيل الدخول بنجاح."
                    : "فشلت محاولة تسجيل الدخول.",
                IsSuccessful = isSuccessful,
                FailureReason = failureReason,
                IpAddress = HttpContext.Connection
                    .RemoteIpAddress?.ToString(),
                UserAgent =
                    Request.Headers["User-Agent"].ToString(),
                CorrelationId = HttpContext.TraceIdentifier
            });
    }

    private string GetSafeReturnUrl(string? returnUrl)
    {
        if (!string.IsNullOrWhiteSpace(returnUrl) &&
            Url.IsLocalUrl(returnUrl))
        {
            return returnUrl;
        }

        return string.Empty;
    }

    public class InputModel
    {
        [Required(ErrorMessage = "البريد الإلكتروني مطلوب.")]
        [EmailAddress(
            ErrorMessage = "صيغة البريد الإلكتروني غير صحيحة.")]
        [StringLength(
            256,
            ErrorMessage = "البريد الإلكتروني طويل جدًا.")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "كلمة المرور مطلوبة.")]
        [DataType(DataType.Password)]
        [StringLength(
            128,
            ErrorMessage = "كلمة المرور طويلة جدًا.")]
        public string Password { get; set; } = string.Empty;

        public bool RememberMe { get; set; }
    }
}