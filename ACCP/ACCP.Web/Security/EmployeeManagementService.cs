using System.ComponentModel.DataAnnotations;
using System.Data;
using ACCP.Application.Auditing;
using ACCP.Application.Security;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace ACCP.Web.Security;

public sealed record EmployeeAccountSummary(
    Guid Id, string FullName, string Email, bool IsActive,
    bool TwoFactorEnabled, bool HasAdminRole, DateTime CreatedAtUtc,
    string ConcurrencyToken);

public sealed record EmployeeOperationResult(bool Succeeded, string Message, Guid? EmployeeId = null);

/// <summary>
/// Current ADMIN accounts may manage OFFICER accounts. Caller input never
/// selects the administrator identity or the role granted to a new employee.
/// Email/password changes preserve MFA and revoke previously issued sessions.
/// </summary>
public sealed class EmployeeManagementService
{
    private readonly CaseAuthorizationService _authorization;
    private readonly IServiceScopeFactory _scopeFactory;

    public EmployeeManagementService(CaseAuthorizationService authorization, IServiceScopeFactory scopeFactory)
    {
        _authorization = authorization;
        _scopeFactory = scopeFactory;
    }

    public async Task<List<EmployeeAccountSummary>> GetOfficersAsync()
    {
        await RequireAdminAsync();
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var officerIds = db.UserRoles.Join(db.Roles, member => member.RoleId, role => role.Id,
            (member, role) => new { member.UserId, role.Name })
            .Where(member => member.Name == IdentityRoles.Officer).Select(member => member.UserId);
        var adminIds = db.UserRoles.Join(db.Roles, member => member.RoleId, role => role.Id,
            (member, role) => new { member.UserId, role.Name })
            .Where(member => member.Name == IdentityRoles.Admin).Select(member => member.UserId);

        // Explicit projection excludes password hashes, security stamps, and tokens.
        // ConcurrencyToken is an optimistic edit token, not a login credential.
        return await db.Users.AsNoTracking().Where(user => officerIds.Contains(user.Id))
            .OrderByDescending(user => user.CreatedAtUtc).ThenBy(user => user.Id)
            .Select(user => new EmployeeAccountSummary(user.Id, user.FullName, user.Email ?? string.Empty,
                user.IsActive, user.TwoFactorEnabled, adminIds.Contains(user.Id),
                user.CreatedAtUtc, user.ConcurrencyStamp ?? string.Empty)).ToListAsync();
    }

    public async Task<EmployeeOperationResult> CreateOfficerAsync(string fullName, string email, string password)
    {
        var actor = await RequireAdminAsync();
        var name = fullName?.Trim() ?? string.Empty;
        var address = email?.Trim() ?? string.Empty;
        if (name.Length is < 2 or > 120 || name.Any(char.IsControl))
            return Failure("اسم الموظف يجب أن يكون بين حرفين و120 حرفًا.");
        if (address.Length > 256 || !new EmailAddressAttribute().IsValid(address) || string.IsNullOrWhiteSpace(address))
            return Failure("أدخل بريدًا إلكترونيًا صالحًا.");
        if (string.IsNullOrWhiteSpace(password) || password.Length is < 12 or > 128)
            return Failure("كلمة مرور الموظف يجب أن تكون بين 12 و128 حرفًا.");

        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        if (!await db.Roles.AnyAsync(role => role.Name == IdentityRoles.Officer))
            return Failure("دور الموظف غير مهيّأ في النظام.");
        if (await users.FindByEmailAsync(address) is not null)
            return Failure("هذا البريد الإلكتروني مستخدم بالفعل.");

        // Account creation, role assignment, and audit commit together.
        await using var transaction = await db.Database.BeginTransactionAsync();
        var employee = new ApplicationUser
        {
            Id = Guid.NewGuid(), UserName = address, Email = address, FullName = name,
            IsActive = true, LockoutEnabled = true, EmailConfirmed = false,
            CreatedAtUtc = DateTime.UtcNow
        };
        var result = await users.CreateAsync(employee, password);
        if (!result.Succeeded) return IdentityFailure(result);
        result = await users.AddToRoleAsync(employee, IdentityRoles.Officer);
        if (!result.Succeeded) return IdentityFailure(result);
        await EnsureSameAdminAsync(actor.UserId);
        await WriteAuditAsync(scope.ServiceProvider, db, actor.UserId, employee.Id,
            AuditAction.AccountCreated, "تم إنشاء حساب موظف ومنحه دور الموظف.");
        await transaction.CommitAsync();
        return new(true, "تم إنشاء حساب الموظف بنجاح.", employee.Id);
    }

    public async Task<EmployeeOperationResult> SetOfficerActiveAsync(
        Guid employeeId, bool isActive, string expectedConcurrencyToken)
    {
        var actor = await RequireAdminAsync();
        if (employeeId == Guid.Empty || employeeId == actor.UserId)
            return Failure("لا يمكن تغيير حالة حسابك من إدارة الموظفين.");
        if (string.IsNullOrWhiteSpace(expectedConcurrencyToken) || expectedConcurrencyToken.Length > 128)
            return Failure("حدّث قائمة الموظفين قبل تغيير حالة الحساب.");

        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        // Keep the target's role membership stable while its status is changed.
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        var employee = await users.FindByIdAsync(employeeId.ToString());
        if (employee is null || !await users.IsInRoleAsync(employee, IdentityRoles.Officer) ||
            await users.IsInRoleAsync(employee, IdentityRoles.Admin))
            return Failure("يمكن إدارة حسابات الموظفين فقط؛ حسابات المديرين محمية.");
        if (!string.Equals(employee.ConcurrencyStamp, expectedConcurrencyToken, StringComparison.Ordinal))
            return Failure("تغيّرت بيانات الحساب. حدّث القائمة وحاول مجددًا.");
        if (employee.IsActive == isActive)
            return new(true, isActive ? "الحساب مفعّل بالفعل." : "الحساب معطّل بالفعل.", employee.Id);

        employee.IsActive = isActive;
        // This persists the changed status and a new security stamp through Identity.
        // Both activation and deactivation invalidate previously issued sessions.
        var result = await users.UpdateSecurityStampAsync(employee);
        if (!result.Succeeded) return IdentityFailure(result);
        await EnsureSameAdminAsync(actor.UserId);
        await WriteAuditAsync(scope.ServiceProvider, db, actor.UserId, employee.Id,
            isActive ? AuditAction.AccountActivated : AuditAction.AccountDeactivated,
            isActive ? "تم تفعيل حساب الموظف وإلغاء جلساته السابقة."
                : "تم تعطيل حساب الموظف وإلغاء جلساته السابقة.");
        await transaction.CommitAsync();
        return new(true, isActive ? "تم تفعيل الحساب. يجب تسجيل الدخول مجددًا."
            : "تم تعطيل الحساب وإلغاء جلساته السابقة.", employee.Id);
    }

    public async Task<EmployeeOperationResult> ChangeOfficerEmailAsync(
        Guid employeeId, string newEmail, string expectedConcurrencyToken)
    {
        var actor = await RequireAdminAsync();
        var requestError = ValidateEditRequest(actor.UserId, employeeId, expectedConcurrencyToken);
        if (requestError is not null) return requestError;
        var address = newEmail?.Trim() ?? string.Empty;
        if (address.Length > 256 || address.Any(char.IsControl) ||
            string.IsNullOrWhiteSpace(address) || !new EmailAddressAttribute().IsValid(address))
            return Failure("أدخل بريدًا إلكترونيًا صالحًا.");

        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        var employee = await GetEditableOfficerAsync(users, employeeId);
        if (employee is null)
            return Failure("يمكن إدارة حسابات الموظفين فقط؛ حسابات المديرين محمية.");
        if (!string.Equals(employee.ConcurrencyStamp, expectedConcurrencyToken, StringComparison.Ordinal))
            return Failure("تغيّرت بيانات الحساب. حدّث القائمة وحاول مجددًا.");
        if (string.Equals(employee.Email, address, StringComparison.Ordinal) &&
            string.Equals(employee.UserName, address, StringComparison.Ordinal))
            return new(true, "البريد الإلكتروني مطابق للبريد الحالي.", employee.Id);

        // Both email and username are login identifiers; neither may belong to another account.
        var emailOwner = await users.FindByEmailAsync(address);
        var nameOwner = await users.FindByNameAsync(address);
        if ((emailOwner is not null && emailOwner.Id != employee.Id) ||
            (nameOwner is not null && nameOwner.Id != employee.Id))
            return Failure("هذا البريد الإلكتروني مستخدم بالفعل.");

        // Identity normalizes and validates each identifier. The transaction prevents
        // a half-completed edit when updating the second identifier or auditing fails.
        var result = await users.SetEmailAsync(employee, address);
        if (!result.Succeeded) return IdentityFailure(result);
        result = await users.SetUserNameAsync(employee, address);
        if (!result.Succeeded) return IdentityFailure(result);
        employee.EmailConfirmed = false;
        result = await users.UpdateSecurityStampAsync(employee);
        if (!result.Succeeded) return IdentityFailure(result);
        await EnsureSameAdminAsync(actor.UserId);
        await WriteAuditAsync(scope.ServiceProvider, db, actor.UserId, employee.Id,
            AuditAction.AccountEmailChanged,
            "تم تغيير بريد الموظف واسم تسجيل دخوله وإلغاء جلساته السابقة بواسطة المدير.");
        await transaction.CommitAsync();
        return new(true, "تم تغيير البريد. يسجّل الموظف دخوله بالبريد الجديد وكود التحقق المعتاد.", employee.Id);
    }

    public async Task<EmployeeOperationResult> ResetOfficerPasswordAsync(
        Guid employeeId, string newPassword, string expectedConcurrencyToken)
    {
        var actor = await RequireAdminAsync();
        var requestError = ValidateEditRequest(actor.UserId, employeeId, expectedConcurrencyToken);
        if (requestError is not null) return requestError;
        if (string.IsNullOrWhiteSpace(newPassword) || newPassword.Length is < 12 or > 128)
            return Failure("كلمة مرور الموظف يجب أن تكون بين 12 و128 حرفًا.");

        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccpDbContext>();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        var employee = await GetEditableOfficerAsync(users, employeeId);
        if (employee is null)
            return Failure("يمكن إدارة حسابات الموظفين فقط؛ حسابات المديرين محمية.");
        if (!string.Equals(employee.ConcurrencyStamp, expectedConcurrencyToken, StringComparison.Ordinal))
            return Failure("تغيّرت بيانات الحساب. حدّث القائمة وحاول مجددًا.");

        // Only this already-authorized server operation generates the reset token.
        // Neither the old password nor a caller-supplied reset token is required.
        var resetToken = await users.GeneratePasswordResetTokenAsync(employee);
        var result = await users.ResetPasswordAsync(employee, resetToken, newPassword);
        if (!result.Succeeded) return IdentityFailure(result);
        employee.AccessFailedCount = 0;
        employee.LockoutEnd = null;
        // Preserve IsActive, role membership, authenticator key, and TwoFactorEnabled.
        result = await users.UpdateSecurityStampAsync(employee);
        if (!result.Succeeded) return IdentityFailure(result);
        await EnsureSameAdminAsync(actor.UserId);
        await WriteAuditAsync(scope.ServiceProvider, db, actor.UserId, employee.Id,
            AuditAction.AccountPasswordReset,
            "تم تعيين كلمة مرور جديدة للموظف وإلغاء جلساته السابقة بواسطة المدير.");
        await transaction.CommitAsync();
        return new(true, "تم تعيين كلمة مرور جديدة وإلغاء الجلسات السابقة. كود التحقق يبقى مطلوبًا.", employee.Id);
    }

    private static EmployeeOperationResult? ValidateEditRequest(
        Guid actorId, Guid employeeId, string expectedConcurrencyToken)
    {
        if (employeeId == Guid.Empty || employeeId == actorId)
            return Failure("لا يمكن تعديل حسابك من إدارة الموظفين.");
        if (string.IsNullOrWhiteSpace(expectedConcurrencyToken) || expectedConcurrencyToken.Length > 128)
            return Failure("حدّث قائمة الموظفين قبل تعديل الحساب.");
        return null;
    }

    private static async Task<ApplicationUser?> GetEditableOfficerAsync(
        UserManager<ApplicationUser> users, Guid employeeId)
    {
        var employee = await users.FindByIdAsync(employeeId.ToString());
        if (employee is null || !await users.IsInRoleAsync(employee, IdentityRoles.Officer) ||
            await users.IsInRoleAsync(employee, IdentityRoles.Admin)) return null;
        return employee;
    }

    private async Task<CaseAccessActor> RequireAdminAsync()
    {
        var actor = await _authorization.GetCurrentActorAsync();
        if (actor is not null && actor.HasRole(IdentityRoles.Admin)) return actor;
        throw new UnauthorizedAccessException("إدارة حسابات الموظفين متاحة لمدير نظام فعّال فقط.");
    }

    private async Task EnsureSameAdminAsync(Guid actorId)
    {
        var current = await RequireAdminAsync();
        if (current.UserId != actorId)
            throw new UnauthorizedAccessException("تغيّرت جلسة الحساب أثناء العملية. أعد تسجيل الدخول.");
    }

    private static async Task WriteAuditAsync(IServiceProvider services, AccpDbContext db,
        Guid actorId, Guid employeeId, AuditAction action, string description)
    {
        var email = await db.Users.AsNoTracking().Where(user => user.Id == actorId)
            .Select(user => user.Email).FirstOrDefaultAsync();
        await services.GetRequiredService<IAuditService>().WriteAsync(new AuditLogRequest
        {
            Action = action, ActorUserId = actorId, ActorEmail = email, ActorRole = IdentityRoles.Admin,
            EntityType = nameof(ApplicationUser), EntityId = employeeId,
            Description = description, IsSuccessful = true
        });
    }

    private static EmployeeOperationResult Failure(string message) => new(false, message);

    private static EmployeeOperationResult IdentityFailure(IdentityResult result)
    {
        var codes = result.Errors.Select(error => error.Code).ToHashSet(StringComparer.Ordinal);
        if (codes.Contains("DuplicateEmail") || codes.Contains("DuplicateUserName"))
            return Failure("هذا البريد الإلكتروني مستخدم بالفعل.");
        if (codes.Contains("ConcurrencyFailure"))
            return Failure("تغيّرت بيانات الحساب أثناء العملية. حدّث القائمة وحاول مجددًا.");
        if (codes.Any(code => code.StartsWith("Password", StringComparison.Ordinal)))
            return Failure("كلمة المرور يجب أن تحتوي على حرف كبير وصغير ورقم ورمز خاص، مع الالتزام بالطول المطلوب.");
        return Failure("تعذر تنفيذ عملية الحساب. تحقق من البيانات وحاول مجددًا.");
    }
}