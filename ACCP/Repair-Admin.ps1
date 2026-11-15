param(
    [Parameter(Mandatory = $true)][string]$Email,
    [Parameter(Mandatory = $true)][string]$Password,
    [string]$ProjectRoot = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
$accpRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
$accpWebPath = Join-Path $accpRoot 'ACCP.Web'
$accpInfrastructureProject = Join-Path $accpRoot 'ACCP.Infrastructure\ACCP.Infrastructure.csproj'
if (!(Test-Path -LiteralPath $accpInfrastructureProject) -or
    !(Test-Path -LiteralPath (Join-Path $accpWebPath 'appsettings.json'))) {
    throw 'Save this script in the ACCP solution folder, or pass -ProjectRoot.'
}
if ([string]::IsNullOrWhiteSpace($Email) -or [string]::IsNullOrWhiteSpace($Password)) {
    throw 'Email and password must not be empty.'
}

$accpWorkDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('ACCP.AdminRecovery.' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $accpWorkDirectory | Out-Null
$accpTempProject = Join-Path $accpWorkDirectory 'AdminRecovery.csproj'
$accpProjectReference = [System.Security.SecurityElement]::Escape($accpInfrastructureProject)

$accpProjectSource = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
    <ProjectReference Include="$accpProjectReference" />
  </ItemGroup>
</Project>
"@

$accpProgramSource = @'
using System.Data;
using System.ComponentModel.DataAnnotations;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Data.SqlClient;

public static class RecoveryProgram
{
    public static async Task<int> Main()
    {
        try
        {
            var root = Environment.GetEnvironmentVariable("ACCP_RECOVERY_ROOT")
                ?? throw new InvalidOperationException("Missing project folder.");
            var email = Environment.GetEnvironmentVariable("ACCP_RECOVERY_EMAIL")
                ?? throw new InvalidOperationException("Missing email.");
            var password = Environment.GetEnvironmentVariable("ACCP_RECOVERY_PASSWORD")
                ?? throw new InvalidOperationException("Missing password.");
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Path.Combine(root, "ACCP.Web"))
                .AddJsonFile("appsettings.json", optional: false)
                .AddJsonFile("appsettings.Development.json", optional: true)
                .AddEnvironmentVariables()
                .Build();
            var connection = configuration.GetConnectionString("DefaultConnection")
                ?? throw new InvalidOperationException("Missing DefaultConnection.");

            var services = new ServiceCollection();
            services.AddLogging(options => options.SetMinimumLevel(LogLevel.Warning));
            services.AddDataProtection();
            services.AddDbContext<AccpDbContext>(options => options.UseSqlServer(connection));
            services.AddIdentityCore<ApplicationUser>(RecoveryCore.ConfigureIdentity)
                .AddRoles<IdentityRole<Guid>>()
                .AddEntityFrameworkStores<AccpDbContext>()
                .AddDefaultTokenProviders();
            await using var provider = services.BuildServiceProvider();
            await using var scope = provider.CreateAsyncScope();
            var sp = scope.ServiceProvider;
            var db = sp.GetRequiredService<AccpDbContext>();
            var user = await RecoveryCore.RepairAsync(db,
                sp.GetRequiredService<UserManager<ApplicationUser>>(),
                sp.GetRequiredService<RoleManager<IdentityRole<Guid>>>(), email, password);

            Console.WriteLine("ADMIN_READY: " + user.Email);
            Console.WriteLine("Password verified. Account active; ADMIN role verified; lockout cleared.");
            Console.WriteLine("Database: " + db.Database.GetDbConnection().Database);
            Console.WriteLine("TwoFactorEnabled: " + user.TwoFactorEnabled);
            return 0;
        }
        catch (Exception ex)
        {
            // Only safe operation codes are printed, never connection strings or credentials.
            var detail = ex is RecoveryException safe ? safe.Message
                : ex is SqlException sql ? "SQL_ERROR_" + sql.Number
                : ex.GetType().Name;
            Console.Error.WriteLine("RECOVERY_FAILED: " + detail);
            return 1;
        }
    }
}

public static class RecoveryCore
{
    // Scoped to this one-shot recovery process. The Web project's password
    // validators and normal registration policies remain unchanged.
    public static void ConfigureIdentity(IdentityOptions options)
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 8;
        options.Password.RequireUppercase = true;
        options.Password.RequireDigit = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireLowercase = false;
    }

    public static async Task<ApplicationUser> RepairAsync(AccpDbContext db,
        UserManager<ApplicationUser> users, RoleManager<IdentityRole<Guid>> roles,
        string email, string password)
    {
        email = email.Trim();
        if (!new EmailAddressAttribute().IsValid(email))
            throw new RecoveryException("INVALID_EMAIL_FORMAT");
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        if (!await roles.RoleExistsAsync(IdentityRoles.Admin))
            Ensure(await roles.CreateAsync(new IdentityRole<Guid> { Id = Guid.NewGuid(), Name = IdentityRoles.Admin }));

        var user = await users.FindByEmailAsync(email);
        if (user is null)
        {
            user = new ApplicationUser
            {
                Id = Guid.NewGuid(), UserName = email, Email = email,
                FullName = "System administrator", IsActive = true,
                EmailConfirmed = false, CreatedAtUtc = DateTime.UtcNow
            };
            Ensure(await users.CreateAsync(user, password));
        }
        else
        {
            user.IsActive = true;
            var token = await users.GeneratePasswordResetTokenAsync(user);
            Ensure(await users.ResetPasswordAsync(user, token, password));
        }
        if (!await users.IsInRoleAsync(user, IdentityRoles.Admin))
            Ensure(await users.AddToRoleAsync(user, IdentityRoles.Admin));
        Ensure(await users.SetLockoutEndDateAsync(user, null));
        Ensure(await users.ResetAccessFailedCountAsync(user));
        Ensure(await users.UpdateSecurityStampAsync(user));
        if (!user.IsActive || !await users.CheckPasswordAsync(user, password) ||
            !await users.IsInRoleAsync(user, IdentityRoles.Admin) || await users.IsLockedOutAsync(user))
            throw new RecoveryException("VERIFICATION_FAILED");

        // Existing authenticator keys, MFA flags and recovery codes are preserved.
        await transaction.CommitAsync();
        return user;
    }

    private static void Ensure(IdentityResult result)
    {
        if (!result.Succeeded)
            throw new RecoveryException("IDENTITY_ERROR: " + string.Join(",", result.Errors.Select(error => error.Code)));
    }
}
public sealed class RecoveryException : Exception
{
    public RecoveryException(string message) : base(message) { }
}
'@

$accpSucceeded = $false
try {
    Set-Content -LiteralPath $accpTempProject -Value $accpProjectSource -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $accpWorkDirectory 'Program.cs') -Value $accpProgramSource -Encoding UTF8
    $env:ACCP_RECOVERY_ROOT = $accpRoot
    $env:ACCP_RECOVERY_EMAIL = $Email.Trim()
    $env:ACCP_RECOVERY_PASSWORD = $Password
    & dotnet run --project $accpTempProject --verbosity quiet
    if ($LASTEXITCODE -ne 0) {
        throw 'Recovery did not complete. Send the RECOVERY_FAILED line or build error.'
    }
    $accpSucceeded = $true
}
finally {
    foreach ($accpVariable in @('ACCP_RECOVERY_ROOT', 'ACCP_RECOVERY_EMAIL', 'ACCP_RECOVERY_PASSWORD',
        'ACCP_ADMIN_EMAIL', 'ACCP_ADMIN_PASSWORD', 'ACCP_OFFICER_RESET_EMAIL', 'ACCP_OFFICER_RESET_PASSWORD')) {
        Remove-Item -LiteralPath "Env:\$accpVariable" -ErrorAction SilentlyContinue
    }
    $Password = $null
    Remove-Item -LiteralPath $accpWorkDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

if ($accpSucceeded) {
    Write-Host "Ready. Sign in with: $Email"
    & dotnet run --project $accpWebPath
}
