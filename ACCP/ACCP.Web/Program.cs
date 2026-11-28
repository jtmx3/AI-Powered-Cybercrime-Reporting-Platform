using System.Security.Claims;
using System.Threading.RateLimiting;
using ACCP.Application.Auditing;
using ACCP.Application.Cases;
using ACCP.Application.EvidenceManagement;
using ACCP.Application.Notifications;
using ACCP.Application.Security;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using ACCP.Infrastructure.Services;
using ACCP.Web.Components;
using ACCP.Web.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using EvidenceEntity = ACCP.Domain.Entities.Evidence;
using EvidenceRevisionEntity = ACCP.Domain.Entities.EvidenceRevision;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpContextAccessor();

var connectionString =
    builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException(
        "Database connection string was not found.");

builder.Services.AddDbContext<AccpDbContext>(options =>
    options.UseSqlServer(connectionString));

// خدمات الصلاحيات وإدارة الموظفين.
builder.Services.AddScoped<CaseAuthorizationService>();
builder.Services.AddScoped<EmployeeManagementService>();

builder.Services.AddScoped<
    ACCP.Web.Security.AdminOfficerWorkloadService>();

builder.Services.AddScoped<
    ACCP.Web.Security.AdminCaseReassignmentService>();

builder.Services.AddScoped<
    ACCP.Web.Security.AdminCaseReopeningService>();

builder.Services.AddScoped<
    ACCP.Web.Security.EmployeeTwoFactorResetService>();

// سجل التدقيق.
builder.Services.AddScoped<
    ACCP.Infrastructure.Services.AuditService>();

builder.Services.AddScoped<
    IAuditService,
    ACCP.Web.Security.AuthorizedAuditService>();

// الإشعارات.
builder.Services.AddScoped<
    ACCP.Infrastructure.Services.NotificationService>();

builder.Services.AddScoped<
    INotificationService,
    ACCP.Web.Security.AuthorizedNotificationService>();

builder.Services.AddDataProtection();

// استعادة كلمة المرور.
builder.Services.AddOptions<SmtpPasswordResetOptions>()
    .Bind(builder.Configuration.GetSection("Email:Smtp"));

builder.Services.AddScoped<
    IPasswordResetEmailSender,
    SmtpPasswordResetEmailSender>();

builder.Services.AddScoped<ReporterPasswordResetService>();

// القضايا والطلبات والأدلة.
builder.Services.AddScoped<
    ICaseService,
    AuthorizedCaseService>();

builder.Services.AddScoped<
    ACCP.Application.CaseStaffing.ICaseStaffRequestService,
    ACCP.Web.Security.AuthorizedCaseStaffRequestService>();

builder.Services.AddScoped<
    IEvidenceService,
    AuthorizedEvidenceService>();

// الهوية.
builder.Services
    .AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
    {
        options.User.RequireUniqueEmail = true;

        options.Password.RequiredLength = 8;
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;

        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan =
            TimeSpan.FromMinutes(15);
    })
    .AddEntityFrameworkStores<AccpDbContext>()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "ACCP.Authentication";
    options.LoginPath = "/login";
    options.AccessDeniedPath = "/access-denied";
    options.ExpireTimeSpan = TimeSpan.FromHours(2);
    options.SlidingExpiration = true;
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy =
        CookieSecurePolicy.SameAsRequest;
});

builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    options.OnRefreshingPrincipal = context =>
    {
        var current = context.CurrentPrincipal;
        var refreshed = context.NewPrincipal;

        if (current is null || refreshed is null)
            return Task.CompletedTask;

        var oldId = current.FindFirstValue(
            ClaimTypes.NameIdentifier);

        var newId = refreshed.FindFirstValue(
            ClaimTypes.NameIdentifier);

        var oldStamp = current.FindFirstValue(
            "AspNet.Identity.SecurityStamp");

        var newStamp = refreshed.FindFirstValue(
            "AspNet.Identity.SecurityStamp");

        if (StaffTwoFactorFlow.HasCompletedTwoFactor(current) &&
            Guid.TryParse(oldId, out var accountId) &&
            accountId != Guid.Empty &&
            Guid.TryParse(newId, out var refreshedId) &&
            refreshedId == accountId &&
            !string.IsNullOrWhiteSpace(oldStamp) &&
            string.Equals(
                oldStamp,
                newStamp,
                StringComparison.Ordinal) &&
            refreshed.Identity is ClaimsIdentity identity &&
            identity.AuthenticationType ==
                IdentityConstants.ApplicationScheme &&
            !identity.HasClaim("amr", "mfa"))
        {
            identity.AddClaim(new Claim("amr", "mfa"));
        }

        if (Guid.TryParse(oldId, out var exemptAccountId) &&
            exemptAccountId != Guid.Empty &&
            Guid.TryParse(newId, out var refreshedExemptId) &&
            refreshedExemptId == exemptAccountId &&
            !string.IsNullOrWhiteSpace(oldStamp) &&
            string.Equals(
                oldStamp,
                newStamp,
                StringComparison.Ordinal) &&
            current.HasClaim(
                LocalDevelopmentMfaExemption.ClaimType,
                LocalDevelopmentMfaExemption.ClaimValue) &&
            current.FindFirst(
                LocalDevelopmentMfaExemption.ExpiresAtClaimType) is { } expiryClaim &&
            refreshed.Identity is ClaimsIdentity exemptIdentity &&
            exemptIdentity.AuthenticationType ==
                IdentityConstants.ApplicationScheme &&
            !exemptIdentity.HasClaim(
                LocalDevelopmentMfaExemption.ClaimType,
                LocalDevelopmentMfaExemption.ClaimValue))
        {
            exemptIdentity.AddClaim(new Claim(
                LocalDevelopmentMfaExemption.ClaimType,
                LocalDevelopmentMfaExemption.ClaimValue));
            exemptIdentity.AddClaim(new Claim(
                LocalDevelopmentMfaExemption.ExpiresAtClaimType,
                expiryClaim.Value));
        }

        return Task.CompletedTask;
    };
});

builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddRazorPages();

// تحديد محاولات استعادة كلمة المرور.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode =
        StatusCodes.Status429TooManyRequests;

    options.AddPolicy(
        "reporter-recovery-request",
        context => RecoveryPartition(context, 3));

    options.AddPolicy(
        "reporter-recovery-reset",
        context => RecoveryPartition(context, 10));

    options.OnRejected = async (context, cancellationToken) =>
    {
        var response = context.HttpContext.Response;

        response.StatusCode =
            StatusCodes.Status429TooManyRequests;

        response.ContentType = "text/plain; charset=utf-8";
        response.Headers["Cache-Control"] = "no-store";

        if (context.Lease.TryGetMetadata(
            MetadataName.RetryAfter,
            out var retryAfter))
        {
            response.Headers["Retry-After"] =
                Math.Max(
                    1,
                    Math.Ceiling(retryAfter.TotalSeconds))
                .ToString(
                    System.Globalization.CultureInfo.InvariantCulture);
        }

        await response.WriteAsync(
            "وصلت للحد المسموح من محاولات الاستعادة. انتظر بضع دقائق ثم حاول مجددًا.",
            cancellationToken);
    };
});

// خدمات المحادثات الحالية.
builder.Services.AddScoped<
    ACCP.Application.Chat.ICaseIntakeAssistant,
    ACCP.Web.Services.Chat.UnavailableCaseIntakeAssistant>();

builder.Services.AddScoped<
    ACCP.Application.Chat.IIntakeConversationService,
    ACCP.Web.Services.Chat.IntakeConversationService>();

builder.Services.AddScoped<
    ACCP.Application.Chat.IIntakeAssistantWorkflow,
    ACCP.Web.Services.Chat.IntakeAssistantWorkflow>();

builder.Services.AddScoped<
    ACCP.Application.Chat.IIntakeFormalReportService,
    ACCP.Web.Services.Chat.IntakeFormalReportService>();

builder.Services.AddScoped<
    ACCP.Application.Chat.IStaffIntakeHistoryService,
    ACCP.Web.Services.Chat.StaffIntakeHistoryService>();
builder.Services.AddScoped<
    ACCP.Web.Services.NotificationReadState>();
var app = builder.Build();

var staffHistoryRegistered = app.Services
    .GetRequiredService<
        Microsoft.Extensions.DependencyInjection.IServiceProviderIsService>()
    .IsService(
        typeof(ACCP.Application.Chat.IStaffIntakeHistoryService));

app.Logger.LogInformation(
    "ACCP startup PID {ProcessId}: StaffIntakeHistoryService registered = {Registered}",
    Environment.ProcessId,
    staffHistoryRegistered);

await IdentitySeeder.SeedRolesAsync(app.Services);

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler(
        "/Error",
        createScopeForErrors: true);

    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute(
    "/not-found",
    createScopeForStatusCodePages: true);

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseRequiredOfficerTwoFactor();
app.UseRateLimiter();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();

// عرض الدليل الحالي.
app.MapGet(
    "/evidence/{id:guid}/view",
    async (
        Guid id,
        ClaimsPrincipal currentUser,
        HttpContext httpContext,
        AccpDbContext dbContext,
        IWebHostEnvironment environment,
        CaseAuthorizationService authorizationService,
        IAuditService auditService) =>
    {
        var actor =
            await authorizationService.GetCurrentActorAsync(
                httpContext.RequestAborted);

        if (actor is null)
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.AccessDenied,
                currentUser,
                null,
                nameof(EvidenceEntity),
                id,
                "تم رفض محاولة فتح دليل بسبب هوية مستخدم غير صالحة.",
                false,
                "تعذر التعرف على معرّف المستخدم.");

            return Results.Unauthorized();
        }

        Guid currentUserId = actor.UserId;

        var evidence = await dbContext.EvidenceItems
            .AsNoTracking()
            .Where(item => item.Id == id)
            .Select(item => new
            {
                item.Id,
                item.CyberCaseId,
                item.StorageKey,
                item.ContentType,
                item.IsRestricted,
                item.IsDisclosedToOfficer,
                ReporterId = item.CyberCase.ReporterId
            })
            .FirstOrDefaultAsync(
                httpContext.RequestAborted);

        if (evidence is null)
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.AccessDenied,
                currentUser,
                null,
                nameof(EvidenceEntity),
                id,
                "تم رفض محاولة فتح دليل غير متاح.",
                false,
                "الدليل غير موجود.");

            return Results.NotFound();
        }

        var decision = await authorizationService.CheckAsync(
            evidence.CyberCaseId,
            CasePermission.ReadDetails,
            httpContext.RequestAborted);

        bool isReporter =
            decision.Actor is not null &&
            decision.Actor.HasRole(IdentityRoles.User) &&
            evidence.ReporterId == currentUserId;

        bool officerCanViewEvidence =
            decision.Actor is not null &&
            decision.Actor.HasRole(IdentityRoles.Officer) &&
            (!evidence.IsRestricted ||
             evidence.IsDisclosedToOfficer);

        if (!decision.IsAllowed ||
            decision.Actor?.UserId != currentUserId ||
            (!isReporter && !officerCanViewEvidence))
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.AccessDenied,
                currentUser,
                evidence.CyberCaseId,
                nameof(EvidenceEntity),
                evidence.Id,
                "تم رفض محاولة فتح دليل دون صلاحية.",
                false,
                "المستخدم لا يملك صلاحية عرض الدليل.");

            return Results.NotFound();
        }

        string evidenceRoot = Path.GetFullPath(
            Path.Combine(
                environment.ContentRootPath,
                "App_Data",
                "Evidence"));

        string fullFilePath = Path.GetFullPath(
            Path.Combine(
                evidenceRoot,
                evidence.StorageKey));

        string allowedRoot =
            evidenceRoot.TrimEnd(
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;

        if (!fullFilePath.StartsWith(
            allowedRoot,
            OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal))
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.AccessDenied,
                currentUser,
                evidence.CyberCaseId,
                nameof(EvidenceEntity),
                evidence.Id,
                "تم رفض فتح دليل بسبب مسار تخزين غير صالح.",
                false,
                "فشل التحقق الأمني من مسار الدليل.");

            return Results.NotFound();
        }

        if (!File.Exists(fullFilePath))
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.EvidenceViewed,
                currentUser,
                evidence.CyberCaseId,
                nameof(EvidenceEntity),
                evidence.Id,
                "تعذر فتح الدليل.",
                false,
                "ملف الدليل غير موجود في التخزين.");

            return Results.NotFound();
        }

        if (ShouldWriteViewAudit(httpContext.Request))
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.EvidenceViewed,
                currentUser,
                evidence.CyberCaseId,
                nameof(EvidenceEntity),
                evidence.Id,
                "تم فتح الدليل الحالي.",
                true);
        }

        httpContext.Response.Headers.CacheControl =
            "no-store, no-cache, must-revalidate";

        httpContext.Response.Headers.Pragma = "no-cache";

        httpContext.Response.Headers["X-Content-Type-Options"] =
            "nosniff";

        return Results.File(
            fullFilePath,
            evidence.ContentType,
            enableRangeProcessing: true);
    })
    .RequireAuthorization();

// عرض نسخة محفوظة من الدليل.
app.MapGet(
    "/evidence-revisions/{id:guid}/view",
    async (
        Guid id,
        ClaimsPrincipal currentUser,
        HttpContext httpContext,
        AccpDbContext dbContext,
        IWebHostEnvironment environment,
        CaseAuthorizationService authorizationService,
        IAuditService auditService) =>
    {
        var actor =
            await authorizationService.GetCurrentActorAsync(
                httpContext.RequestAborted);

        if (actor is null)
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.AccessDenied,
                currentUser,
                null,
                nameof(EvidenceRevisionEntity),
                id,
                "تم رفض محاولة فتح نسخة دليل بسبب هوية مستخدم غير صالحة.",
                false,
                "تعذر التعرف على معرّف المستخدم.");

            return Results.Unauthorized();
        }

        Guid currentUserId = actor.UserId;

        var revision = await dbContext.EvidenceRevisions
            .AsNoTracking()
            .Where(item => item.Id == id)
            .Select(item => new
            {
                item.Id,
                item.EvidenceId,
                item.VersionNumber,
                item.StorageKey,
                item.ContentType,
                CyberCaseId = item.Evidence.CyberCaseId,
                ReporterId = item.Evidence.CyberCase.ReporterId,
                item.Evidence.IsRestricted,
                item.Evidence.IsDisclosedToOfficer
            })
            .FirstOrDefaultAsync(
                httpContext.RequestAborted);

        if (revision is null)
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.AccessDenied,
                currentUser,
                null,
                nameof(EvidenceRevisionEntity),
                id,
                "تم رفض محاولة فتح نسخة دليل غير متاحة.",
                false,
                "نسخة الدليل غير موجودة.");

            return Results.NotFound();
        }

        var decision = await authorizationService.CheckAsync(
            revision.CyberCaseId,
            CasePermission.ReadDetails,
            httpContext.RequestAborted);

        bool reporterOwnsCase =
            decision.Actor is not null &&
            decision.Actor.HasRole(IdentityRoles.User) &&
            revision.ReporterId == currentUserId;

        int latestVersionNumber =
            await dbContext.EvidenceRevisions
                .AsNoTracking()
                .Where(item =>
                    item.EvidenceId == revision.EvidenceId)
                .Select(item => (int?)item.VersionNumber)
                .MaxAsync()
            ?? 0;

        bool reporterCanViewRevision =
            reporterOwnsCase &&
            revision.VersionNumber == latestVersionNumber;

        bool officerCanViewRevision =
            decision.Actor is not null &&
            decision.Actor.HasRole(IdentityRoles.Officer) &&
            (!revision.IsRestricted ||
             revision.IsDisclosedToOfficer);

        if (!decision.IsAllowed ||
            decision.Actor?.UserId != currentUserId ||
            (!reporterCanViewRevision &&
             !officerCanViewRevision))
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.AccessDenied,
                currentUser,
                revision.CyberCaseId,
                nameof(EvidenceRevisionEntity),
                revision.Id,
                "تم رفض محاولة فتح نسخة سابقة من الدليل دون صلاحية.",
                false,
                "المستخدم لا يملك صلاحية عرض نسخة الدليل.");

            return Results.NotFound();
        }

        string evidenceRoot = Path.GetFullPath(
            Path.Combine(
                environment.ContentRootPath,
                "App_Data",
                "Evidence"));

        string fullFilePath = Path.GetFullPath(
            Path.Combine(
                evidenceRoot,
                revision.StorageKey));

        string allowedRoot =
            evidenceRoot.TrimEnd(
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;

        if (!fullFilePath.StartsWith(
            allowedRoot,
            OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal))
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.AccessDenied,
                currentUser,
                revision.CyberCaseId,
                nameof(EvidenceRevisionEntity),
                revision.Id,
                "تم رفض فتح نسخة دليل بسبب مسار تخزين غير صالح.",
                false,
                "فشل التحقق الأمني من مسار نسخة الدليل.");

            return Results.NotFound();
        }

        if (!File.Exists(fullFilePath))
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.EvidenceViewed,
                currentUser,
                revision.CyberCaseId,
                nameof(EvidenceRevisionEntity),
                revision.Id,
                "تعذر فتح نسخة الدليل.",
                false,
                "ملف نسخة الدليل غير موجود في التخزين.");

            return Results.NotFound();
        }

        if (ShouldWriteViewAudit(httpContext.Request))
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.EvidenceViewed,
                currentUser,
                revision.CyberCaseId,
                nameof(EvidenceRevisionEntity),
                revision.Id,
                "تم فتح نسخة محفوظة من الدليل.",
                true);
        }

        httpContext.Response.Headers.CacheControl =
            "no-store, no-cache, must-revalidate";

        httpContext.Response.Headers.Pragma = "no-cache";

        httpContext.Response.Headers["X-Content-Type-Options"] =
            "nosniff";

        return Results.File(
            fullFilePath,
            revision.ContentType,
            enableRangeProcessing: true);
    })
    .RequireAuthorization();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapRazorPages();

app.Run();

static RateLimitPartition<string> RecoveryPartition(
    HttpContext context,
    int permitLimit)
{
    if (!HttpMethods.IsPost(context.Request.Method))
    {
        return RateLimitPartition.GetNoLimiter(
            "recovery-form-read");
    }

    var address = context.Connection.RemoteIpAddress;

    if (address?.IsIPv4MappedToIPv6 == true)
        address = address.MapToIPv4();

    return RateLimitPartition.GetFixedWindowLimiter(
        address?.ToString() ?? "unknown-client",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = TimeSpan.FromMinutes(5),
            QueueLimit = 0,
            AutoReplenishment = true
        });
}

static bool ShouldWriteViewAudit(HttpRequest request)
{
    string rangeHeader =
        request.Headers["Range"].ToString();

    return string.IsNullOrWhiteSpace(rangeHeader) ||
           rangeHeader.StartsWith(
               "bytes=0-",
               StringComparison.OrdinalIgnoreCase);
}

static async Task WriteEvidenceAuditAsync(
    IAuditService auditService,
    AccpDbContext dbContext,
    AuditAction action,
    ClaimsPrincipal currentUser,
    Guid? cyberCaseId,
    string entityType,
    Guid entityId,
    string description,
    bool isSuccessful,
    string? failureReason = null)
{
    string? userIdValue =
        currentUser.FindFirstValue(
            ClaimTypes.NameIdentifier);

    Guid? actorUserId =
        Guid.TryParse(
            userIdValue,
            out Guid parsedUserId)
            ? parsedUserId
            : null;

    string? actorEmail = null;
    var roles = new List<string>();

    if (actorUserId is { } accountId &&
        accountId != Guid.Empty)
    {
        actorEmail = await dbContext.Users
            .AsNoTracking()
            .Where(user => user.Id == accountId)
            .Select(user => user.Email)
            .FirstOrDefaultAsync();

        roles = await dbContext.UserRoles
            .Where(userRole => userRole.UserId == accountId)
            .Join(
                dbContext.Roles,
                userRole => userRole.RoleId,
                role => role.Id,
                (_, role) => role.Name)
            .Where(name => name != null)
            .Select(name => name!)
            .ToListAsync();
    }

    string actorRole =
        roles.Contains(IdentityRoles.Officer)
            ? IdentityRoles.Officer
            : roles.Contains(IdentityRoles.User)
                ? IdentityRoles.User
                : roles.Contains(IdentityRoles.Admin)
                    ? IdentityRoles.Admin
                    : "UNKNOWN";

    await auditService.WriteAsync(
        new AuditLogRequest
        {
            Action = action,
            ActorUserId = actorUserId,
            ActorEmail = actorEmail,
            ActorRole = actorRole,
            CyberCaseId = cyberCaseId,
            EntityType = entityType,
            EntityId = entityId,
            Description = description,
            IsSuccessful = isSuccessful,
            FailureReason = failureReason
        });
}
