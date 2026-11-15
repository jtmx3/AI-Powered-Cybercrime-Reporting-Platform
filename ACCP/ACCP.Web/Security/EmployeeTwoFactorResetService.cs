using System.Data;
using ACCP.Application.Auditing;
using ACCP.Application.Security;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ACCP.Web.Security;

public sealed class EmployeeTwoFactorResetService
{
    private readonly CaseAuthorizationService _authorization;
    private readonly IServiceScopeFactory _scopeFactory;

    public EmployeeTwoFactorResetService(
        CaseAuthorizationService authorization,
        IServiceScopeFactory scopeFactory)
    {
        _authorization = authorization;
        _scopeFactory = scopeFactory;
    }

    public async Task<EmployeeOperationResult> ResetOfficerTwoFactorAsync(
        Guid employeeId,
        string reason,
        string expectedConcurrencyToken,
        CancellationToken cancellationToken = default)
    {
        var actor = await RequireAdminAsync(cancellationToken);

        if (employeeId == Guid.Empty ||
            employeeId == actor.UserId)
        {
            return Failure(
                "لا يمكن إعادة تهيئة تحقق حسابك من إدارة الموظفين.");
        }

        var cleanReason = reason?.Trim() ?? string.Empty;

        if (cleanReason.Length is < 10 or > 500 ||
            cleanReason.Any(char.IsControl))
        {
            return Failure(
                "اكتب سببًا من 10 إلى 500 حرف في سطر واحد.");
        }

        if (string.IsNullOrWhiteSpace(expectedConcurrencyToken) ||
            expectedConcurrencyToken.Length > 128)
        {
            return Failure(
                "حدّث قائمة الموظفين قبل إعادة تهيئة التحقق.");
        }

        await using var scope = _scopeFactory.CreateAsyncScope();

        var services = scope.ServiceProvider;

        var db = services.GetRequiredService<AccpDbContext>();

        var users = services
            .GetRequiredService<UserManager<ApplicationUser>>();

        var store = services
            .GetRequiredService<IUserStore<ApplicationUser>>();

        if (store is not
                IUserAuthenticatorKeyStore<ApplicationUser> keyStore ||
            store is not
                IUserTwoFactorRecoveryCodeStore<ApplicationUser> recoveryStore)
        {
            return Failure(
                "مخزن الحسابات لا يدعم إعادة تهيئة التحقق.");
        }

        await using var transaction =
            await db.Database.BeginTransactionAsync(
                IsolationLevel.Serializable,
                cancellationToken);

        try
        {
            var employee = await users.FindByIdAsync(
                employeeId.ToString());

            if (employee is null ||
                !await users.IsInRoleAsync(
                    employee,
                    IdentityRoles.Officer) ||
                await users.IsInRoleAsync(
                    employee,
                    IdentityRoles.Admin))
            {
                return Failure(
                    "هذه العملية لحساب الموظف فقط؛ " +
                    "حسابات المديرين محمية.");
            }

            if (!string.Equals(
                    employee.ConcurrencyStamp,
                    expectedConcurrencyToken,
                    StringComparison.Ordinal))
            {
                return Failure(
                    "تغيّرت بيانات الموظف. " +
                    "حدّث القائمة وحاول مجددًا.");
            }

            // إبطال المفتاح السابق دون إظهار المفتاح البديل للمدير.
            await keyStore.SetAuthenticatorKeyAsync(
                employee,
                users.GenerateNewAuthenticatorKey(),
                cancellationToken);

            // إلغاء أي رموز احتياطية تاريخية.
            await recoveryStore.ReplaceCodesAsync(
                employee,
                Array.Empty<string>(),
                cancellationToken);

            var result = await users.SetTwoFactorEnabledAsync(
                employee,
                false);

            if (!result.Succeeded)
            {
                return IdentityFailure(result);
            }

            // إبطال الجلسات وتذاكر التفعيل السابقة.
            result = await users.UpdateSecurityStampAsync(employee);

            if (!result.Succeeded)
            {
                return IdentityFailure(result);
            }

            var currentAdmin = await RequireAdminAsync(
                cancellationToken);

            if (currentAdmin.UserId != actor.UserId)
            {
                throw new UnauthorizedAccessException(
                    "تغيّرت جلسة المدير أثناء العملية. " +
                    "أعد تسجيل الدخول.");
            }

            var adminEmail = await db.Users
                .AsNoTracking()
                .Where(user => user.Id == actor.UserId)
                .Select(user => user.Email)
                .SingleOrDefaultAsync(cancellationToken);

            await services
                .GetRequiredService<IAuditService>()
                .WriteAsync(
                    new AuditLogRequest
                    {
                        Action = AuditAction.TwoFactorDisabled,
                        ActorUserId = actor.UserId,
                        ActorEmail = adminEmail,
                        ActorRole = IdentityRoles.Admin,
                        EntityType = nameof(ApplicationUser),
                        EntityId = employee.Id,
                        Description =
                            "أعاد المدير تهيئة تحقق الموظف " +
                            "وأبطل مفتاحه وجلساته السابقة. " +
                            "يلزم إعداد التحقق مجددًا بعد كلمة المرور. " +
                            $"السبب: {cleanReason}",
                        IsSuccessful = true
                    },
                    cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            return new EmployeeOperationResult(
                true,
                "تمت إعادة تهيئة التحقق وإبطال الجلسات السابقة. " +
                "عند السماح للموظف بالدخول سيعيد ربط " +
                "تطبيق التحقق بعد كلمة المرور.",
                employee.Id);
        }
        catch (DbUpdateException)
        {
            await transaction.RollbackAsync(cancellationToken);

            return Failure(
                "تعذر حفظ العملية. " +
                "حدّث القائمة وحاول مجددًا.");
        }
    }

    private async Task<CaseAccessActor> RequireAdminAsync(
        CancellationToken cancellationToken)
    {
        var actor = await _authorization.GetCurrentActorAsync(
            cancellationToken);

        if (actor is null ||
            !actor.IsAuthenticated ||
            !actor.IsActive ||
            actor.UserId == Guid.Empty ||
            !actor.HasRole(IdentityRoles.Admin))
        {
            throw new UnauthorizedAccessException(
                "إعادة تهيئة تحقق الموظف متاحة لمدير فعّال " +
                "أكمل التحقق الثنائي فقط.");
        }

        return actor;
    }

    private static EmployeeOperationResult IdentityFailure(
        IdentityResult result)
    {
        var concurrencyFailure = result.Errors.Any(
            error => error.Code == "ConcurrencyFailure");

        return Failure(
            concurrencyFailure
                ? "تغيّرت بيانات الموظف أثناء العملية. " +
                  "حدّث القائمة وحاول مجددًا."
                : "تعذرت إعادة تهيئة التحقق. لم تُعتمد العملية.");
    }

    private static EmployeeOperationResult Failure(
        string message) =>
        new(false, message);
}