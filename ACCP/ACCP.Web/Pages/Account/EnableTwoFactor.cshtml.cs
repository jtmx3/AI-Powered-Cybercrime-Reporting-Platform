using System.Data;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using ACCP.Application.Auditing;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using ACCP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace ACCP.Web.Pages.Account;

// The password-verified enrollment cookie grants access to this page only.
// Every handler rechecks that proof or the current authenticated staff account.
[AllowAnonymous]
[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
[RequestSizeLimit(16 * 1024)]
public sealed class EnableTwoFactorModel : PageModel
{
    private const string EnrollmentCookie = "ACCP.TwoFactorEnrollment";
    private const string EnrollmentPurpose = "ACCP.Account.TwoFactorEnrollment.v1";
    private readonly CaseAuthorizationService _authorization;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _users;
    private readonly IUserStore<ApplicationUser> _store;
    private readonly AccpDbContext _db;
    private readonly IAuditService _audit;
    private readonly ILogger<EnableTwoFactorModel> _logger;

    public EnableTwoFactorModel(CaseAuthorizationService authorization,
        SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> users,
        IUserStore<ApplicationUser> store, AccpDbContext db, IAuditService audit,
        ILogger<EnableTwoFactorModel> logger)
    {
        _authorization = authorization;
        _signInManager = signInManager;
        _users = users;
        _store = store;
        _db = db;
        _audit = audit;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string AccountEmail { get; private set; } = string.Empty;
    public bool TwoFactorEnabled { get; private set; }
    public bool EnrollmentPending { get; private set; }
    public string SharedKey { get; private set; } = string.Empty;
    public string AuthenticatorUri { get; private set; } = string.Empty;
    public IReadOnlyList<string> RecoveryCodes { get; private set; } = Array.Empty<string>();
    public bool EnrollmentCompleted { get; private set; }

    private bool EnrollmentOnly => User.Identity?.IsAuthenticated != true;

    public async Task<IActionResult> OnGetAsync()
    {
        PrepareResponse();
        var user = await GetStaffAsync();
        if (user is null) return await EndSessionAsync();
        ShowAccount(user);
        if (user.TwoFactorEnabled) DeleteEnrollment();
        else if (ReadEnrollment(user) is { } enrollment) ShowEnrollment(user, enrollment);
        else if (EnrollmentOnly) StartEnrollment(user);
        else DeleteEnrollment();
        return Page();
    }

    public async Task<IActionResult> OnPostBeginAsync()
    {
        PrepareResponse();
        var user = await GetStaffAsync();
        if (user is null) return await EndSessionAsync();
        ShowAccount(user);
        DeleteEnrollment();
        if (user.TwoFactorEnabled) { ClearInputs(); return Page(); }

        // The first-login flow has already checked the password. It carries no
        // application session and cannot access staff pages or case services.
        if (EnrollmentOnly)
        {
            ClearInputs();
            StartEnrollment(user);
            return Page();
        }

        var password = Input.Password ?? string.Empty;
        if (!ModelState.IsValid || password.Length == 0 || password.Length > 128)
            return Error("أدخل كلمة مرور حسابك الحالية.");

        var expectedStamp = user.SecurityStamp;
        Microsoft.AspNetCore.Identity.SignInResult result;
        try
        {
            // Reauthentication does not issue a new application login cookie.
            result = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
        }
        finally { ClearInputs(); }

        if (!result.Succeeded)
        {
            if (result.IsLockedOut || result.IsNotAllowed) return await EndSessionAsync();
            return Error("كلمة المرور غير صحيحة. حاول مجددًا.");
        }

        // A disable, role removal or stamp change during reauthentication cancels setup.
        user = await GetStaffAsync();
        if (user is null || user.TwoFactorEnabled ||
            !string.Equals(user.SecurityStamp, expectedStamp, StringComparison.Ordinal))
            return await EndSessionAsync();

        StartEnrollment(user);
        return Page();
    }

    public async Task<IActionResult> OnPostConfirmAsync()
    {
        PrepareResponse();
        var user = await GetStaffAsync();
        if (user is null) return await EndSessionAsync();
        ShowAccount(user);
        if (user.TwoFactorEnabled) { ClearInputs(); DeleteEnrollment(); return Page(); }

        var enrollment = ReadEnrollment(user);
        if (enrollment is null)
        {
            DeleteEnrollment();
            if (EnrollmentOnly) return LocalRedirect("/account/two-factor");
            return Error("انتهت جلسة التفعيل. أدخل كلمة المرور لبدء التفعيل مجددًا.");
        }
        ShowEnrollment(user, enrollment);
        var code = (Input.Code ?? string.Empty).Replace(" ", string.Empty).Replace("-", string.Empty);
        var validInput = ModelState.IsValid && code.Length == 6 && code.All(ch => ch >= '0' && ch <= '9');
        ClearInputs();
        if (!validInput) return Error("أدخل الرمز الحالي من تطبيق المصادقة، المكوّن من 6 أرقام.");

        bool incorrectCode = false;
        string[] codes = [];
        try
        {
            await using var transaction = await _db.Database.BeginTransactionAsync(
                IsolationLevel.Serializable, HttpContext.RequestAborted);
            // Recheck through this transaction's connection, before any writes.
            // The authorization service uses another scope: calling it after a
            // user update here can wait on this transaction's own SQL Server lock.
            user = await LoadStaffAsync(user.Id);
            if (user is null || user.TwoFactorEnabled ||
                !string.Equals(user.SecurityStamp, enrollment.SecurityStamp, StringComparison.Ordinal))
                throw new EnrollmentChangedException();

            if (_store is not IUserAuthenticatorKeyStore<ApplicationUser> keyStore)
                throw new InvalidOperationException("Authenticator storage is unavailable.");
            // Do not replace the persisted authenticator key until proof succeeds.
            // The store stages this token in the same DbContext/transaction.
            await keyStore.SetAuthenticatorKeyAsync(user, enrollment.Key, HttpContext.RequestAborted);
            if (!await _users.VerifyTwoFactorTokenAsync(user,
                    _users.Options.Tokens.AuthenticatorTokenProvider, code))
            {
                incorrectCode = true;
                await transaction.RollbackAsync(HttpContext.RequestAborted);
                _db.ChangeTracker.Clear();
            }
            else
            {
                var roles = await _users.GetRolesAsync(user);
                var isOfficer = roles.Contains(IdentityRoles.Officer);
                Ensure(await _users.SetTwoFactorEnabledAsync(user, true));
                if (isOfficer)
                {
                    // No backup credentials are generated for OFFICER accounts,
                    // including ADMIN/OFFICER accounts. Clear any historical codes
                    // within the same transaction that enables the verified key.
                    if (_store is not IUserTwoFactorRecoveryCodeStore<ApplicationUser> recoveryStore)
                        throw new InvalidOperationException("Recovery credential storage is unavailable.");
                    await recoveryStore.ReplaceCodesAsync(user, Array.Empty<string>(), HttpContext.RequestAborted);
                }
                else
                {
                    codes = (await _users.GenerateNewTwoFactorRecoveryCodesAsync(user, 10))?.ToArray() ?? [];
                    if (codes.Length != 10) throw new InvalidOperationException("Recovery code creation failed.");
                }
                Ensure(await _users.ResetAccessFailedCountAsync(user));
                Ensure(await _users.UpdateSecurityStampAsync(user));
                await _audit.WriteAsync(new AuditLogRequest
                {
                    Action = AuditAction.TwoFactorEnabled,
                    ActorUserId = user.Id, ActorEmail = user.Email,
                    ActorRole = roles.Contains(IdentityRoles.Admin) ? IdentityRoles.Admin : IdentityRoles.Officer,
                    EntityType = nameof(ApplicationUser), EntityId = user.Id,
                    Description = isOfficer
                        ? "تم تفعيل المصادقة الثنائية بكود تطبيق التحقق لحساب الموظف."
                        : "تم تفعيل المصادقة الثنائية وإنشاء رموز الاسترداد للحساب.",
                    IsSuccessful = true,
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                    UserAgent = Request.Headers["User-Agent"].ToString(),
                    CorrelationId = HttpContext.TraceIdentifier
                }, HttpContext.RequestAborted);
                await transaction.CommitAsync(HttpContext.RequestAborted);
            }
        }
        catch (EnrollmentChangedException)
        {
            _db.ChangeTracker.Clear();
            return await EndSessionAsync();
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _logger.LogError(exception,
                "Failed to confirm two-factor enrollment for account {UserId}.", user?.Id);
            _db.ChangeTracker.Clear();
            // Transaction disposal rolls back the key, MFA flag, codes and stamps.
            // Preserve the password-verified ticket and pending key so a transient
            // persistence failure does not force a new authenticator enrollment.
            return Error(
                "تعذر حفظ التفعيل الآن. احتفظ بمفتاح الربط نفسه، ثم أدخل الرمز الحالي من التطبيق وحاول مجددًا.");
        }

        if (incorrectCode)
        {
            // Transaction has been disposed; do not save its unverified key.
            user = await GetStaffAsync();
            if (user is null || user.TwoFactorEnabled ||
                !string.Equals(user.SecurityStamp, enrollment.SecurityStamp, StringComparison.Ordinal))
                return await EndSessionAsync();
            var increment = await _users.AccessFailedAsync(user);
            if (!increment.Succeeded || await _users.IsLockedOutAsync(user))
                return await EndSessionAsync();
            return Error("رمز التحقق غير صحيح. أدخل الرمز الحالي من تطبيق المصادقة.");
        }

        HideEnrollment();
        DeleteEnrollment();
        TwoFactorEnabled = true;
        // Stamp rotation revokes every old session. Show credentials only in this
        // response, never in cookies, TempData, URLs, logs or subsequent requests.
        await _signInManager.SignOutAsync();
        StaffTwoFactorFlow.ClearEnrollment(HttpContext);
        RecoveryCodes = codes;
        EnrollmentCompleted = true;
        return Page();
    }

    public async Task<IActionResult> OnPostCancelAsync()
    {
        PrepareResponse();
        ClearInputs();
        DeleteEnrollment();
        var user = await GetStaffAsync();
        if (user is null || EnrollmentOnly) return await EndSessionAsync();
        ShowAccount(user);
        return Page();
    }

    private async Task<ApplicationUser?> GetStaffAsync()
    {
        if (EnrollmentOnly)
            return await StaffTwoFactorFlow.GetEnrollmentUserAsync(HttpContext);
        // An authenticated account never falls back to another account's
        // pending cookie if its own current permissions are rejected.
        var actor = await _authorization.GetCurrentActorAsync(HttpContext.RequestAborted);
        if (actor is null || (!actor.HasRole(IdentityRoles.Admin) && !actor.HasRole(IdentityRoles.Officer)))
            return null;
        return await LoadStaffAsync(actor.UserId);
    }

    private async Task<ApplicationUser?> LoadStaffAsync(Guid id)
    {
        if (EnrollmentOnly)
        {
            // Same request DbContext, including during the confirmation
            // transaction; no second connection can wait on our own writes.
            var pending = await StaffTwoFactorFlow.GetEnrollmentUserAsync(HttpContext);
            return pending?.Id == id ? pending : null;
        }
        if (!Guid.TryParse(User.FindFirstValue(_users.Options.ClaimsIdentity.UserIdClaimType), out var principalId) ||
            principalId != id || User.Identity?.IsAuthenticated != true) return null;
        var user = await _users.FindByIdAsync(id.ToString());
        if (user is null) return null;
        await _db.Entry(user).ReloadAsync(HttpContext.RequestAborted);
        var stamp = User.FindFirstValue(_users.Options.ClaimsIdentity.SecurityStampClaimType);
        if (_db.Entry(user).State == EntityState.Detached || !user.IsActive ||
            string.IsNullOrWhiteSpace(stamp) || string.IsNullOrWhiteSpace(user.SecurityStamp) ||
            !string.Equals(user.SecurityStamp, stamp, StringComparison.Ordinal) ||
            await _users.IsLockedOutAsync(user)) return null;
        var roles = await _users.GetRolesAsync(user);
        return roles.Contains(IdentityRoles.Admin) || roles.Contains(IdentityRoles.Officer) ? user : null;
    }

    private void StartEnrollment(ApplicationUser user)
    {
        var enrollment = new Enrollment(user.Id, user.SecurityStamp!, _users.GenerateNewAuthenticatorKey());
        Response.Cookies.Append(EnrollmentCookie,
            Protector().Protect(JsonSerializer.Serialize(enrollment), StaffTwoFactorFlow.EnrollmentLifetime), CookieOptions());
        ShowEnrollment(user, enrollment);
    }

    private Enrollment? ReadEnrollment(ApplicationUser user)
    {
        if (!Request.Cookies.TryGetValue(EnrollmentCookie, out var value)) return null;
        try
        {
            var enrollment = JsonSerializer.Deserialize<Enrollment>(Protector().Unprotect(value));
            return enrollment is not null && enrollment.UserId == user.Id &&
                !string.IsNullOrWhiteSpace(enrollment.SecurityStamp) &&
                string.Equals(enrollment.SecurityStamp, user.SecurityStamp, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(enrollment.Key) && enrollment.Key.Length is >= 16 and <= 128 &&
                enrollment.Key.All(ch => ch is >= 'A' and <= 'Z' or >= '2' and <= '7')
                ? enrollment : null;
        }
        catch (CryptographicException) { return null; }
        catch (JsonException) { return null; }
    }

    private void ShowAccount(ApplicationUser user)
    {
        AccountEmail = user.Email ?? user.UserName ?? string.Empty;
        TwoFactorEnabled = user.TwoFactorEnabled;
    }

    private void ShowEnrollment(ApplicationUser user, Enrollment enrollment)
    {
        ShowAccount(user);
        EnrollmentPending = true;
        SharedKey = enrollment.Key;
        AuthenticatorUri = "otpauth://totp/" + Uri.EscapeDataString("ACCP:" + AccountEmail) +
            "?secret=" + Uri.EscapeDataString(enrollment.Key) + "&issuer=ACCP&digits=6";
    }

    private void HideEnrollment()
    {
        EnrollmentPending = false;
        SharedKey = string.Empty;
        AuthenticatorUri = string.Empty;
    }

    private ITimeLimitedDataProtector Protector() =>
        HttpContext.RequestServices.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(EnrollmentPurpose).ToTimeLimitedDataProtector();

    private CookieOptions CookieOptions() => new()
    {
        HttpOnly = true, Secure = Request.IsHttps, SameSite = SameSiteMode.Strict,
        Path = "/", IsEssential = true, MaxAge = StaffTwoFactorFlow.EnrollmentLifetime
    };

    private void DeleteEnrollment()
    {
        var options = CookieOptions();
        options.MaxAge = TimeSpan.Zero;
        Response.Cookies.Delete(EnrollmentCookie, options);
    }

    private void PrepareResponse()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
    }

    private void ClearInputs()
    {
        Input.Password = string.Empty;
        Input.Code = string.Empty;
        ModelState.Remove("Input.Password");
        ModelState.Remove("Input.Code");
    }

    private IActionResult Error(string message)
    {
        ClearInputs();
        ModelState.AddModelError(string.Empty, message);
        return Page();
    }

    private async Task<IActionResult> EndSessionAsync()
    {
        // Preserve the existing denial for a signed-in non-staff user.
        if (!EnrollmentOnly && !User.IsInRole(IdentityRoles.Admin) &&
            !User.IsInRole(IdentityRoles.Officer)) return Forbid();
        ClearInputs();
        HideEnrollment();
        DeleteEnrollment();
        StaffTwoFactorFlow.ClearEnrollment(HttpContext);
        await _signInManager.SignOutAsync();
        return LocalRedirect("/login");
    }

    private static void Ensure(IdentityResult result)
    {
        if (!result.Succeeded) throw new InvalidOperationException("Identity update failed.");
    }

    private sealed record Enrollment(Guid UserId, string SecurityStamp, string Key);
    private sealed class EnrollmentChangedException : Exception { }

    public sealed class InputModel
    {
        public string Password { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
    }
}
