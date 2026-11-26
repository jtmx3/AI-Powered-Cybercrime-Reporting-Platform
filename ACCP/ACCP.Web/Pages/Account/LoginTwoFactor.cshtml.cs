using ACCP.Application.Auditing;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text.Json;

namespace ACCP.Web.Pages.Account;

// The page is anonymous because the password step has not issued an application
// login yet. The protected Identity two-factor cookie identifies the account.
[AllowAnonymous]
[EnableRateLimiting("auth-login")]
[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
[RequestSizeLimit(16 * 1024)]
public sealed class LoginTwoFactorModel : PageModel
{
    private const string PendingCookieName = "ACCP.PendingTwoFactor";
    private const string PendingPurpose = "ACCP.Login.PendingTwoFactor.v1";
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AccpDbContext _db;
    private readonly IAuditService _audit;

    public LoginTwoFactorModel(SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager, AccpDbContext db, IAuditService audit)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _db = db;
        _audit = audit;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    [BindProperty(SupportsGet = true)]
    public bool RememberMe { get; set; }

    public string ReturnUrl { get; private set; } = string.Empty;
    public bool ChallengeAvailable { get; private set; } = true;
    // Derived only from current database roles. This is never bound from a form.
    public bool CanUseRecoveryCodes { get; private set; }

    // Call only from LoginModel after PasswordSignInAsync returns RequiresTwoFactor.
    // Identity's temporary user-id cookie does not contain the security stamp.
    // This additional protected, expiring cookie binds that challenge to the
    // password-verified account's stamp and its server-selected persistence flag.
    public static void BindPendingLogin(HttpContext context, ApplicationUser user, bool rememberMe)
    {
        if (!user.IsActive || !user.TwoFactorEnabled || string.IsNullOrWhiteSpace(user.SecurityStamp))
            throw new InvalidOperationException("لا يمكن بدء التحقق لهذا الحساب.");
        var protector = context.RequestServices.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(PendingPurpose).ToTimeLimitedDataProtector();
        var payload = JsonSerializer.Serialize(new PendingLogin(user.Id, user.SecurityStamp, rememberMe));
        context.Response.Cookies.Append(PendingCookieName, protector.Protect(payload, TimeSpan.FromMinutes(5)),
            PendingCookieOptions(context));
    }

    public async Task<IActionResult> OnGetAsync(string? returnUrl = null)
    {
        PrepareResponse(returnUrl);
        if (await GetPendingUserAsync() is null) return RestartLogin();
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        PrepareResponse(returnUrl);
        var user = await GetPendingUserAsync();
        if (user is null) return RestartLogin();

        // OFFICER membership takes precedence, including ADMIN/OFFICER accounts.
        // Reject even a valid, previously generated recovery code before Identity
        // can redeem it or issue an application login cookie.
        if (Input.UseRecoveryCode && !CanUseRecoveryCodes)
            return await RejectOfficerRecoveryAsync(user);

        var submitted = Input.UseRecoveryCode ? Input.RecoveryCode : Input.Code;
        var code = (submitted ?? string.Empty).Replace(" ", string.Empty);
        // Recovery-code separators are part of Identity's generated credential.
        if (!Input.UseRecoveryCode) code = code.Replace("-", string.Empty);
        // Bounded, conditional validation: only the selected form is required.
        if (!ModelState.IsValid || code.Length == 0 || code.Length > 128 ||
            (!Input.UseRecoveryCode && (code.Length != 6 || code.Any(ch => ch < '0' || ch > '9'))))
        {
            ClearCodes();
            ModelState.AddModelError(string.Empty, Input.UseRecoveryCode
                ? "أدخل رمز استرداد صالحًا." : "أدخل رمز تطبيق المصادقة المكوّن من 6 أرقام.");
            return Page();
        }

        var expectedStamp = user.SecurityStamp;
        var recovery = Input.UseRecoveryCode;
        var failedBefore = user.AccessFailedCount;
        Microsoft.AspNetCore.Identity.SignInResult result;
        try
        {
            // RememberMe controls cookie persistence only. Remembering the
            // second-factor device is deliberately unavailable in this flow.
            result = recovery
                ? await _signInManager.TwoFactorRecoveryCodeSignInAsync(code)
                : await _signInManager.TwoFactorAuthenticatorSignInAsync(code, RememberMe, rememberClient: false);
        }
        finally { ClearCodes(); }

        if (result.Succeeded)
        {
            DeleteBoundCookie();
            // Identity tracks the user within this request. Reload after issuing
            // the cookie so a concurrent disable/stamp change cancels this login.
            await _db.Entry(user).ReloadAsync();
            if (_db.Entry(user).State == EntityState.Detached || !user.IsActive || !user.TwoFactorEnabled ||
                !string.Equals(user.SecurityStamp, expectedStamp, StringComparison.Ordinal))
            {
                await _signInManager.SignOutAsync();
                ChallengeAvailable = false;
                await WriteAuditAsync(user, false, "تغيّرت حالة الحساب أو جلسة التحقق أثناء تسجيل الدخول.");
                ModelState.AddModelError(string.Empty, "تغيّرت حالة الحساب. أعد تسجيل الدخول.");
                return Page();
            }

            // Recheck membership after Identity sign-in as well. A newly assigned
            // officer role must not retain a login just completed with recovery.
            CanUseRecoveryCodes = !await _userManager.IsInRoleAsync(user, IdentityRoles.Officer);
            if (recovery && !CanUseRecoveryCodes)
            {
                await _signInManager.SignOutAsync();
                return await RejectOfficerRecoveryAsync(user);
            }

            try { await WriteAuditAsync(user, true, null); }
            catch
            {
                // Never leave a successful login cookie after audit persistence fails.
                await _signInManager.SignOutAsync();
                ChallengeAvailable = false;
                ModelState.AddModelError(string.Empty, "تعذر إكمال تسجيل الدخول. حاول تسجيل الدخول مجددًا.");
                return Page();
            }

            if (!string.IsNullOrEmpty(ReturnUrl)) return LocalRedirect(ReturnUrl);
            if (await _userManager.IsInRoleAsync(user, IdentityRoles.Admin)) return LocalRedirect("/admin/employees");
            if (await _userManager.IsInRoleAsync(user, IdentityRoles.Officer)) return LocalRedirect("/officer/dashboard");
            return LocalRedirect("/cases");
        }

        // Identity's authenticator path applies lockout. Recovery-code failure
        // can return Failed without incrementing; cover it without double-counting.
        if (recovery && !result.IsLockedOut && !result.IsNotAllowed && _userManager.SupportsUserLockout)
        {
            await _db.Entry(user).ReloadAsync();
            if (user.AccessFailedCount == failedBefore && !await _userManager.IsLockedOutAsync(user))
            {
                var increment = await _userManager.AccessFailedAsync(user);
                if (!increment.Succeeded)
                {
                    await ClearPendingCookieAsync();
                    ChallengeAvailable = false;
                    ModelState.AddModelError(string.Empty, "تعذر إكمال التحقق. أعد تسجيل الدخول.");
                    return Page();
                }
            }
            if (await _userManager.IsLockedOutAsync(user)) result = Microsoft.AspNetCore.Identity.SignInResult.LockedOut;
        }

        await WriteAuditAsync(user, false, result.IsLockedOut
            ? "تم قفل الحساب مؤقتًا بعد محاولات تحقق فاشلة."
            : "فشل التحقق من العامل الثاني.");

        if (result.IsLockedOut || result.IsNotAllowed)
        {
            await ClearPendingCookieAsync();
            ChallengeAvailable = false;
            ModelState.AddModelError(string.Empty, result.IsLockedOut
                ? "تم إيقاف تسجيل الدخول مؤقتًا بسبب تكرار المحاولات الخاطئة. حاول لاحقًا."
                : "تعذر إكمال تسجيل الدخول لهذا الحساب.");
        }
        else
        {
            ModelState.AddModelError(string.Empty, recovery
                ? "رمز الاسترداد غير صحيح أو استُخدم سابقًا."
                : "رمز التحقق غير صحيح. أدخل الرمز الحالي من تطبيق المصادقة.");
        }
        return Page();
    }

    public async Task<IActionResult> OnPostCancelAsync(string? returnUrl = null)
    {
        PrepareResponse(returnUrl);
        ClearCodes();
        await ClearPendingCookieAsync();
        return RestartLogin();
    }

    private async Task<ApplicationUser?> GetPendingUserAsync()
    {
        var ticket = await HttpContext.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme);
        if (!ticket.Succeeded || ticket.Principal is null) return null;
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user is null) { await ClearPendingCookieAsync(); return null; }

        await _db.Entry(user).ReloadAsync();
        if (_db.Entry(user).State == EntityState.Detached || !user.IsActive || !user.TwoFactorEnabled)
        {
            await ClearPendingCookieAsync();
            return null;
        }
        PendingLogin? pending = null;
        if (Request.Cookies.TryGetValue(PendingCookieName, out var protectedState))
        {
            try
            {
                var protector = HttpContext.RequestServices.GetRequiredService<IDataProtectionProvider>()
                    .CreateProtector(PendingPurpose).ToTimeLimitedDataProtector();
                pending = JsonSerializer.Deserialize<PendingLogin>(protector.Unprotect(protectedState));
            }
            catch (CryptographicException) { }
            catch (JsonException) { }
        }
        if (pending is null || pending.UserId != user.Id || string.IsNullOrWhiteSpace(pending.SecurityStamp) ||
            !string.Equals(pending.SecurityStamp, user.SecurityStamp, StringComparison.Ordinal))
        {
            await ClearPendingCookieAsync();
            return null;
        }
        RememberMe = pending.RememberMe;
        CanUseRecoveryCodes = !await _userManager.IsInRoleAsync(user, IdentityRoles.Officer);
        return user;
    }

    private async Task<IActionResult> RejectOfficerRecoveryAsync(ApplicationUser user)
    {
        ClearCodes();
        Input.UseRecoveryCode = false;
        ModelState.Remove("Input.UseRecoveryCode");
        CanUseRecoveryCodes = false;
        ChallengeAvailable = false;
        await ClearPendingCookieAsync();
        await WriteAuditAsync(user, false, "رموز الاسترداد غير مسموحة لحسابات الموظفين.");
        ModelState.AddModelError(string.Empty,
            "حساب الموظف يتطلب كود تطبيق التحقق. أعد تسجيل الدخول واستخدم الكود الحالي من التطبيق.");
        return Page();
    }

    private void PrepareResponse(string? returnUrl)
    {
        ReturnUrl = !string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : string.Empty;
        CanUseRecoveryCodes = false;
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
    }

    private IActionResult RestartLogin() => LocalRedirect(string.IsNullOrEmpty(ReturnUrl)
        ? "/login" : "/login?returnUrl=" + Uri.EscapeDataString(ReturnUrl));

    private async Task ClearPendingCookieAsync()
    {
        DeleteBoundCookie();
        await HttpContext.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);
    }

    private void DeleteBoundCookie()
    {
        var options = PendingCookieOptions(HttpContext);
        options.MaxAge = TimeSpan.Zero;
        Response.Cookies.Delete(PendingCookieName, options);
    }

    private static CookieOptions PendingCookieOptions(HttpContext context) => new()
    {
        HttpOnly = true, Secure = context.Request.IsHttps, SameSite = SameSiteMode.Strict,
        Path = "/", IsEssential = true, MaxAge = TimeSpan.FromMinutes(5)
    };

    private sealed record PendingLogin(Guid UserId, string SecurityStamp, bool RememberMe);

    private void ClearCodes()
    {
        Input.Code = string.Empty;
        Input.RecoveryCode = string.Empty;
        ModelState.Remove("Input.Code");
        ModelState.Remove("Input.RecoveryCode");
    }

    private async Task WriteAuditAsync(ApplicationUser user, bool successful, string? reason)
    {
        var role = await _userManager.IsInRoleAsync(user, IdentityRoles.Admin) ? IdentityRoles.Admin
            : await _userManager.IsInRoleAsync(user, IdentityRoles.Officer) ? IdentityRoles.Officer : IdentityRoles.User;
        await _audit.WriteAsync(new AuditLogRequest
        {
            Action = successful ? AuditAction.UserLoggedIn : AuditAction.UserLoginFailed,
            ActorUserId = user.Id, ActorEmail = user.Email, ActorRole = role,
            EntityType = nameof(ApplicationUser), EntityId = user.Id,
            Description = successful ? "تم تسجيل الدخول بالمصادقة الثنائية." : "فشلت محاولة التحقق من العامل الثاني.",
            IsSuccessful = successful, FailureReason = reason,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = Request.Headers["User-Agent"].ToString(), CorrelationId = HttpContext.TraceIdentifier
        });
    }

    public sealed class InputModel
    {
        public string Code { get; set; } = string.Empty;
        public string RecoveryCode { get; set; } = string.Empty;
        public bool UseRecoveryCode { get; set; }
    }
}