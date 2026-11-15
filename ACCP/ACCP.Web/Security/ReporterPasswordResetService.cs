using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using ACCP.Application.Auditing;
using ACCP.Application.Security;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace ACCP.Web.Security;

public sealed class ReporterPasswordResetService
{
    public const string RequestConfirmation =
        "إذا كان البريد مرتبطًا بحساب مشتكي مؤهل، سيصلك رابط استعادة كلمة المرور.";
    private const string InvalidLink =
        "رابط الاستعادة غير صالح أو انتهت صلاحيته. اطلب رابطًا جديدًا.";
    private static readonly TimeSpan LinkLifetime = TimeSpan.FromMinutes(30);
    private readonly IServiceScopeFactory _scopes;
    private readonly IPasswordResetEmailSender _emailSender;
    private readonly ITimeLimitedDataProtector _protector;
    private readonly IConfiguration _configuration;
    private readonly IHostEnvironment _environment;
    private readonly IHttpContextAccessor _http;

    public ReporterPasswordResetService(
        IServiceScopeFactory scopes,
        IPasswordResetEmailSender emailSender,
        IDataProtectionProvider protection,
        IConfiguration configuration,
        IHostEnvironment environment,
        IHttpContextAccessor http)
    {
        _scopes = scopes;
        _emailSender = emailSender;
        _protector = protection
            .CreateProtector("ACCP.ReporterPasswordReset.v1")
            .ToTimeLimitedDataProtector();
        _configuration = configuration;
        _environment = environment;
        _http = http;
    }

    // The page must always use RequestConfirmation, including unknown and
    // staff emails. Request limiting belongs on the anonymous HTTP endpoint.
    public async Task RequestResetAsync(
        string? email,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var address = email?.Trim() ?? string.Empty;
        if (address.Length is 0 or > 256 || address.Any(char.IsControl) ||
            !new EmailAddressAttribute().IsValid(address)) return;

        // Resolve the site address from trusted configuration, never Host or
        // forwarded headers supplied by the person requesting the email.
        var baseAddress = GetPublicBaseAddress();
        await using var scope = _scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByEmailAsync(address);
        if (user is null || !await IsEligibleReporterAsync(users, user)) return;

        var identityToken = await users.GeneratePasswordResetTokenAsync(user);
        var ticket = new ResetTicket(
            user.Id, user.NormalizedEmail!, user.SecurityStamp!, identityToken);
        var protectedTicket = _protector.Protect(
            JsonSerializer.Serialize(ticket), LinkLifetime);
        var link = new Uri(baseAddress.AbsoluteUri.TrimEnd('/') +
            "/reset-password?token=" + Uri.EscapeDataString(protectedTicket));

        cancellationToken.ThrowIfCancellationRequested();
        await _emailSender.SendPasswordResetLinkAsync(
            user.Email!, link, cancellationToken);
    }

    public async Task<ReporterPasswordResetResult> ResetPasswordAsync(
        string? protectedTicket,
        string? newPassword,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var ticket = ReadTicket(protectedTicket);
        if (ticket is null) return Failure(InvalidLink);

        await using var scope = _scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var audit = scope.ServiceProvider.GetRequiredService<IAuditService>();
        try
        {
            // Authorization, password/stamp changes, and the audit commit
            // together. Concurrent role changes cannot bypass this check.
            await using var transaction = await db.Database.BeginTransactionAsync(
                IsolationLevel.Serializable, cancellationToken);
            var user = await users.FindByIdAsync(ticket.UserId.ToString());
            if (user is null || !await IsEligibleReporterAsync(users, user) ||
                !string.Equals(user.SecurityStamp, ticket.SecurityStamp, StringComparison.Ordinal) ||
                !string.Equals(user.NormalizedEmail, ticket.NormalizedEmail, StringComparison.Ordinal) ||
                !await users.VerifyUserTokenAsync(user,
                    users.Options.Tokens.PasswordResetTokenProvider,
                    UserManager<ApplicationUser>.ResetPasswordTokenPurpose,
                    ticket.IdentityToken))
                return Failure(InvalidLink);

            if (string.IsNullOrEmpty(newPassword) || newPassword.Length > 128)
                return Failure("أدخل كلمة مرور جديدة لا تتجاوز 128 حرفًا.");

            // Identity applies the same password validators as registration.
            var reset = await users.ResetPasswordAsync(
                user, ticket.IdentityToken, newPassword);
            if (!reset.Succeeded) return Failure(PasswordError(reset));

            Ensure(await users.ResetAccessFailedCountAsync(user));
            if (users.SupportsUserLockout)
                Ensure(await users.SetLockoutEndDateAsync(user, null));
            Ensure(await users.UpdateSecurityStampAsync(user));

            var context = _http.HttpContext;
            await audit.WriteAsync(new AuditLogRequest
            {
                Action = AuditAction.AccountPasswordReset,
                ActorUserId = user.Id,
                ActorEmail = user.Email,
                ActorRole = IdentityRoles.User,
                EntityType = nameof(ApplicationUser),
                EntityId = user.Id,
                Description = "تمت استعادة كلمة مرور حساب المشتكي عبر رابط البريد الإلكتروني.",
                IsSuccessful = true,
                IpAddress = context?.Connection.RemoteIpAddress?.ToString(),
                UserAgent = context?.Request.Headers["User-Agent"].ToString(),
                CorrelationId = context?.TraceIdentifier
            }, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new(true, "تم تغيير كلمة المرور. سجّل الدخول بكلمة المرور الجديدة.");
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Disposing the transaction rolls back credentials and audit on
            // any failure. Never include tokens or passwords in errors/logs.
            return Failure("تعذر إكمال الاستعادة. حاول مرة أخرى.");
        }
    }

    private static async Task<bool> IsEligibleReporterAsync(
        UserManager<ApplicationUser> users, ApplicationUser user)
    {
        if (!user.IsActive || string.IsNullOrWhiteSpace(user.Email) ||
            string.IsNullOrWhiteSpace(user.NormalizedEmail) ||
            string.IsNullOrWhiteSpace(user.SecurityStamp) ||
            !await users.HasPasswordAsync(user)) return false;
        var roles = await users.GetRolesAsync(user);
        // Staff and mixed-role accounts never use reporter self-service.
        return roles.Count == 1 && roles.Contains(IdentityRoles.User);
    }

    private Uri GetPublicBaseAddress()
    {
        var configured = _configuration["AccountRecovery:PublicBaseUrl"]?.Trim();
        if (!Uri.TryCreate(configured, UriKind.Absolute, out var address) ||
            !string.IsNullOrEmpty(address.UserInfo) ||
            !string.IsNullOrEmpty(address.Query) ||
            !string.IsNullOrEmpty(address.Fragment) ||
            (address.Scheme != Uri.UriSchemeHttps &&
             !(_environment.IsDevelopment() && address.IsLoopback &&
               address.Scheme == Uri.UriSchemeHttp)))
            throw new InvalidOperationException(
                "AccountRecovery:PublicBaseUrl must be a trusted HTTPS site address.");
        return address;
    }

    private ResetTicket? ReadTicket(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 16_384) return null;
        try
        {
            var ticket = JsonSerializer.Deserialize<ResetTicket>(_protector.Unprotect(value));
            return ticket is not null && ticket.UserId != Guid.Empty &&
                !string.IsNullOrWhiteSpace(ticket.NormalizedEmail) &&
                !string.IsNullOrWhiteSpace(ticket.SecurityStamp) &&
                !string.IsNullOrWhiteSpace(ticket.IdentityToken) ? ticket : null;
        }
        catch (CryptographicException) { return null; }
        catch (JsonException) { return null; }
    }

    private static string PasswordError(IdentityResult result)
    {
        if (result.Errors.Any(error => error.Code == "InvalidToken")) return InvalidLink;
        if (result.Errors.Any(error => error.Code.StartsWith("Password", StringComparison.Ordinal)))
            return "كلمة المرور لا تحقق شروط الأمان. استخدم كلمة أطول تحتوي حروفًا كبيرة وصغيرة ورقمًا ورمزًا.";
        return "تعذر تغيير كلمة المرور. حاول مرة أخرى.";
    }

    private static ReporterPasswordResetResult Failure(string message) => new(false, message);

    private static void Ensure(IdentityResult result)
    {
        if (!result.Succeeded) throw new InvalidOperationException("Identity account update failed.");
    }

    private sealed record ResetTicket(
        Guid UserId, string NormalizedEmail, string SecurityStamp, string IdentityToken);
}

public sealed record ReporterPasswordResetResult(bool Succeeded, string Message);