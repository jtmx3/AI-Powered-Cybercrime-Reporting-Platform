using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace ACCP.Infrastructure.Identity;

public static class IdentitySeeder
{
    private const string AdminEmailVariable =
        "ACCP_ADMIN_EMAIL";

    private const string AdminPasswordVariable =
        "ACCP_ADMIN_PASSWORD";

    private const string OfficerResetEmailVariable =
        "ACCP_OFFICER_RESET_EMAIL";

    private const string OfficerResetPasswordVariable =
        "ACCP_OFFICER_RESET_PASSWORD";

    public static async Task SeedRolesAsync(
        IServiceProvider serviceProvider)
    {
        using IServiceScope scope =
            serviceProvider.CreateScope();

        RoleManager<IdentityRole<Guid>> roleManager =
            scope.ServiceProvider
                .GetRequiredService<
                    RoleManager<IdentityRole<Guid>>>();

        UserManager<ApplicationUser> userManager =
            scope.ServiceProvider
                .GetRequiredService<
                    UserManager<ApplicationUser>>();

        string[] roleNames =
        [
            IdentityRoles.User,
            IdentityRoles.Officer,
            IdentityRoles.Admin
        ];

        foreach (string roleName in roleNames)
        {
            bool roleExists =
                await roleManager.RoleExistsAsync(roleName);

            if (!roleExists)
            {
                IdentityResult roleResult =
                    await roleManager.CreateAsync(
                        new IdentityRole<Guid>(roleName));

                EnsureSucceeded(
                    roleResult,
                    $"تعذر إنشاء الدور {roleName}.");
            }
        }

        await SeedAdminFromEnvironmentAsync(
            userManager);

        await ResetOfficerPasswordFromEnvironmentAsync(
            userManager);
    }

    private static async Task SeedAdminFromEnvironmentAsync(
        UserManager<ApplicationUser> userManager)
    {
        string? adminEmail =
            Environment.GetEnvironmentVariable(
                AdminEmailVariable)
            ?.Trim();

        string? adminPassword =
            Environment.GetEnvironmentVariable(
                AdminPasswordVariable);

        bool emailProvided =
            !string.IsNullOrWhiteSpace(adminEmail);

        bool passwordProvided =
            !string.IsNullOrWhiteSpace(adminPassword);

        // إذا لم تُمرر بيانات المدير، يستمر تشغيل المشروع طبيعيًا.
        if (!emailProvided && !passwordProvided)
        {
            return;
        }

        if (!emailProvided || !passwordProvided)
        {
            throw new InvalidOperationException(
                "يجب تحديد ACCP_ADMIN_EMAIL وACCP_ADMIN_PASSWORD معًا.");
        }

        ApplicationUser? adminUser =
            await userManager.FindByEmailAsync(
                adminEmail!);

        if (adminUser is null)
        {
            adminUser = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = adminEmail,
                Email = adminEmail,
                FullName = "مدير النظام",
                IsActive = true,
                EmailConfirmed = true,
                CreatedAtUtc = DateTime.UtcNow
            };

            IdentityResult createResult =
                await userManager.CreateAsync(
                    adminUser,
                    adminPassword!);

            EnsureSucceeded(
                createResult,
                "تعذر إنشاء حساب المدير.");
        }

        if (!adminUser.IsActive)
        {
            adminUser.IsActive = true;

            IdentityResult updateResult =
                await userManager.UpdateAsync(
                    adminUser);

            EnsureSucceeded(
                updateResult,
                "تعذر تفعيل حساب المدير.");
        }

        bool isAdmin =
            await userManager.IsInRoleAsync(
                adminUser,
                IdentityRoles.Admin);

        if (!isAdmin)
        {
            IdentityResult addToRoleResult =
                await userManager.AddToRoleAsync(
                    adminUser,
                    IdentityRoles.Admin);

            EnsureSucceeded(
                addToRoleResult,
                "تعذر منح الحساب صلاحية المدير.");
        }
    }

    private static async Task ResetOfficerPasswordFromEnvironmentAsync(
        UserManager<ApplicationUser> userManager)
    {
        string? officerEmail =
            Environment.GetEnvironmentVariable(
                OfficerResetEmailVariable)
            ?.Trim();

        string? newPassword =
            Environment.GetEnvironmentVariable(
                OfficerResetPasswordVariable);

        bool emailProvided =
            !string.IsNullOrWhiteSpace(officerEmail);

        bool passwordProvided =
            !string.IsNullOrWhiteSpace(newPassword);

        // بدون المتغيرين لا يتم تنفيذ أي تغيير على حسابات الموظفين.
        if (!emailProvided && !passwordProvided)
        {
            return;
        }

        if (!emailProvided || !passwordProvided)
        {
            throw new InvalidOperationException(
                "يجب تحديد ACCP_OFFICER_RESET_EMAIL و" +
                "ACCP_OFFICER_RESET_PASSWORD معًا.");
        }

        ApplicationUser? officer =
            await userManager.FindByEmailAsync(
                officerEmail!);

        if (officer is null)
        {
            throw new InvalidOperationException(
                $"لم يتم العثور على حساب الموظف {officerEmail}.");
        }

        bool isOfficer =
            await userManager.IsInRoleAsync(
                officer,
                IdentityRoles.Officer);

        if (!isOfficer)
        {
            throw new InvalidOperationException(
                $"الحساب {officerEmail} لا يحمل صلاحية موظف.");
        }

        if (!officer.IsActive)
        {
            throw new InvalidOperationException(
                $"حساب الموظف {officerEmail} غير فعال.");
        }

        string resetToken =
            await userManager.GeneratePasswordResetTokenAsync(
                officer);

        IdentityResult resetResult =
            await userManager.ResetPasswordAsync(
                officer,
                resetToken,
                newPassword!);

        EnsureSucceeded(
            resetResult,
            $"تعذر إعادة تعيين كلمة مرور الموظف {officerEmail}.");
    }

    private static void EnsureSucceeded(
        IdentityResult result,
        string message)
    {
        if (result.Succeeded)
        {
            return;
        }

        string errors = string.Join(
            " | ",
            result.Errors.Select(error =>
                error.Description));

        throw new InvalidOperationException(
            $"{message} {errors}");
    }
}
