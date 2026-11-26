using System.Net;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using ACCP.Application.Auditing;
using ACCP.Application.Cases;
using ACCP.Application.Chat;
using ACCP.Application.EvidenceManagement;
using ACCP.Application.Notifications;
using ACCP.Application.Security;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using ACCP.Infrastructure.Security;
using ACCP.Infrastructure.Services;
using ACCP.Web.Components;
using ACCP.Web.Security;
using ACCP.Web.Services.Chat;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using EvidenceEntity = ACCP.Domain.Entities.Evidence;
using EvidenceRevisionEntity = ACCP.Domain.Entities.EvidenceRevision;

var builder = WebApplication.CreateBuilder(args);

// المرحلة 1: تحصين Kestrel ومنع هجمات MitM وDDoS وSlowloris وضغط الحمولة (Payload Pressure).
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = 15 * 1024 * 1024; // 15 MB hard ceiling
    options.Limits.MaxRequestHeaderCount = 64;
    options.Limits.MaxRequestHeadersTotalSize = 16 * 1024; // 16 KB max headers
    options.Limits.MaxRequestLineSize = 4 * 1024;          // 4 KB max URL line
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(15);
    options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(60);
    options.Limits.MinRequestBodyDataRate =
        new MinDataRate(bytesPerSecond: 240, gracePeriod: TimeSpan.FromSeconds(10));
    options.Limits.MinResponseDataRate =
        new MinDataRate(bytesPerSecond: 240, gracePeriod: TimeSpan.FromSeconds(10));

    var maxConnections = builder.Configuration.GetValue<long?>("Security:Kestrel:MaxConcurrentConnections") ?? 2000;
    var maxUpgraded = builder.Configuration.GetValue<long?>("Security:Kestrel:MaxConcurrentUpgradedConnections") ?? 1000;
    options.Limits.MaxConcurrentConnections = maxConnections;
    options.Limits.MaxConcurrentUpgradedConnections = maxUpgraded;

    bool allowTls12Fallback =
        builder.Environment.IsDevelopment() ||
        builder.Configuration.GetValue<bool>("Security:Tls:AllowTls12Fallback");

    options.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.SslProtocols = allowTls12Fallback
            ? SslProtocols.Tls13 | SslProtocols.Tls12
            : SslProtocols.Tls13;
    });
});

// تخزين مؤقت في الذاكرة للصفحات العامة غير المصادق عليها لتخفيف الضغط عند الذروة.
builder.Services.AddOutputCache(options =>
{
    options.AddPolicy("PublicAnonymousCache", policy =>
        policy.Expire(TimeSpan.FromSeconds(60))
              .SetVaryByHeader("Accept-Encoding")
              .SetLocking(true));
});

builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365);
});

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.ForwardLimit = 1;

    var configuredProxies = builder.Configuration
        .GetSection("Security:ForwardedHeaders:KnownProxies")
        .Get<string[]>();

    if (configuredProxies is { Length: > 0 })
    {
        foreach (var proxy in configuredProxies)
        {
            if (IPAddress.TryParse(proxy?.Trim(), out var ip))
            {
                options.KnownProxies.Add(ip);
            }
        }
    }
});

builder.Services.AddHttpContextAccessor();

// المرحلة 2: إدارة المفاتيح (KMS)، التشفير AES-256-GCM، إخفاء PII، وفحص الأدلة.
builder.Services.AddSingleton<ISecretKeyProvider, EnvironmentKeyManagementService>();
builder.Services.AddSingleton<IDataEncryptionService, AesGcmDataEncryptionService>();
builder.Services.AddSingleton<IPiiMaskingService, PiiMaskingService>();
builder.Services.AddSingleton<IEvidenceMalwareScanner, HeuristicEvidenceMalwareScanner>();

var connectionString =
    builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException(
        "Database connection string was not found.");

builder.Services.AddDbContext<AccpDbContext>(options =>
    options.UseSqlServer(connectionString, sqlOptions =>
        {
            sqlOptions.CommandTimeout(15);
            sqlOptions.MaxBatchSize(100);
            sqlOptions.EnableRetryOnFailure(
                maxRetryCount: 3,
                maxRetryDelay: TimeSpan.FromSeconds(5),
                errorNumbersToAdd: null);
        })
        .ReplaceService<IModelCacheKeyFactory, AccpModelCacheKeyFactory>());

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

// حفظ مفاتيح DataProtection خارج wwwroot مع عزل اسم التطبيق.
var dataProtectionKeysDir = new DirectoryInfo(
    Path.Combine(builder.Environment.ContentRootPath, "App_Data", "DataProtectionKeys"));
dataProtectionKeysDir.Create();

builder.Services.AddDataProtection()
    .SetApplicationName("WATHIQ.ACCP")
    .PersistKeysToFileSystem(dataProtectionKeysDir);

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

// المرحلة 3: تشفير كلمات المرور باستخدام Argon2id مع ترقية تلقائية للتجزئات القديمة.
builder.Services.AddScoped<IPasswordHasher<ApplicationUser>, Argon2idPasswordHasher>();

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
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
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

        return Task.CompletedTask;
    };
});

builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<AuthenticationStateProvider, AccpRevalidatingAuthenticationStateProvider>();

// تحصين دوائر Blazor Server وSignalR ضد استنزاف الذاكرة (Circuit Exhaustion DoS).
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents(options =>
    {
        options.DetailedErrors = builder.Environment.IsDevelopment();
        options.DisconnectedCircuitMaxRetained = 50;
        options.DisconnectedCircuitRetentionPeriod = TimeSpan.FromMinutes(2);
        options.MaxBufferedUnacknowledgedRenderBatches = 10;
    })
    .AddHubOptions(options =>
    {
        options.MaximumReceiveMessageSize = 128 * 1024; // 128 KB max SignalR frame
        options.ClientTimeoutInterval = TimeSpan.FromSeconds(60);
    });

builder.Services.AddRazorPages();

// حماية DDoS وتقييد الطلبات (Global + Auth + Recovery + Evidence).
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode =
        StatusCodes.Status429TooManyRequests;

    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        var path = context.Request.Path.Value ?? string.Empty;
        if (path.StartsWith("/_framework/", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("/lib/", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".css", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".png", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".ico", StringComparison.OrdinalIgnoreCase))
        {
            return RateLimitPartition.GetNoLimiter("static-assets");
        }

        var ip = GetClientIp(context);
        return RateLimitPartition.GetFixedWindowLimiter(
            $"global:{ip}",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 120,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            });
    });

    options.AddPolicy(
        "auth-login",
        context => PostIpPartition(context, "auth-login", permitLimit: 10, windowMinutes: 5));

    // عزل تنزيل وفك تشفير الأدلة (Bulkhead + Rate Limit) لمنع استنزاف الذاكرة تحت الضغط.
    options.AddConcurrencyLimiter("evidence-view", limiterOptions =>
    {
        limiterOptions.PermitLimit = 24;
        limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        limiterOptions.QueueLimit = 32;
    });

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
            "تجاوزت الحد المسموح من المحاولات. انتظر بضع دقائق ثم حاول مجددًا.",
            cancellationToken);
    };
});

// المرحلة 4: حواجز الأمان للذكاء الاصطناعي (AI Guardrails + عزل السياق + System Prompt الصارم).
builder.Services.AddSingleton<IIntakePromptGuard, IntakePromptGuard>();
builder.Services.AddScoped<UnavailableCaseIntakeAssistant>();
builder.Services.AddScoped<ICaseIntakeAssistant>(sp =>
    new GuardedCaseIntakeAssistant(
        sp.GetRequiredService<UnavailableCaseIntakeAssistant>(),
        sp.GetRequiredService<IIntakePromptGuard>(),
        sp.GetRequiredService<ILogger<GuardedCaseIntakeAssistant>>()));

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

app.UseForwardedHeaders();
app.UseAccpSecurityHeaders();

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

// تقييد الطلبات قبل المصادقة واستعلامات قاعدة البيانات لصد الفيضانات بأقل كلفة ممكنة.
app.UseRateLimiter();
app.UseOutputCache();

app.UseAuthentication();
app.UseRequiredOfficerTwoFactor();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();

// عرض الدليل الحالي (مع فك تشفير AES-256-GCM، التحقق من SHA-256، وعزل Sandbox).
app.MapGet(
    "/evidence/{id:guid}/view",
    async (
        Guid id,
        ClaimsPrincipal currentUser,
        HttpContext httpContext,
        AccpDbContext dbContext,
        IWebHostEnvironment environment,
        CaseAuthorizationService authorizationService,
        IAuditService auditService,
        IDataEncryptionService encryptionService) =>
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
                item.OriginalFileName,
                item.Sha256Hash,
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

        byte[] decryptedBytes;
        try
        {
            var storedBytes = await File.ReadAllBytesAsync(fullFilePath, httpContext.RequestAborted);
            decryptedBytes = encryptionService.DecryptBytes(
                storedBytes,
                AesGcmDataEncryptionService.EvidenceFilePurpose);
        }
        catch (CryptographicException)
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.AccessDenied,
                currentUser,
                evidence.CyberCaseId,
                nameof(EvidenceEntity),
                evidence.Id,
                "فشل فك تشفير الدليل أو اكتشاف تلاعب محتمل ببيانات التخزين.",
                false,
                "AES-GCM authentication failed.");

            return Results.StatusCode(StatusCodes.Status500InternalServerError);
        }

        if (!VerifySha256ConstantTime(decryptedBytes, evidence.Sha256Hash))
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.AccessDenied,
                currentUser,
                evidence.CyberCaseId,
                nameof(EvidenceEntity),
                evidence.Id,
                "فشل التحقق من بصمة SHA-256 للدليل؛ تم منع العرض لاحتمال التلاعب.",
                false,
                "SHA-256 integrity mismatch.");

            return Results.StatusCode(StatusCodes.Status500InternalServerError);
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
                "تم فتح الدليل الحالي بعد التحقق من سلامته.",
                true);
        }

        ApplyEvidenceSandboxHeaders(httpContext);

        bool isPdf = string.Equals(evidence.ContentType, "application/pdf", StringComparison.OrdinalIgnoreCase);
        string? downloadName = isPdf ? SanitizeDownloadFileName(evidence.OriginalFileName, "evidence.pdf") : null;

        return Results.File(
            decryptedBytes,
            evidence.ContentType,
            fileDownloadName: downloadName,
            enableRangeProcessing: true);
    })
    .RequireAuthorization()
    .RequireRateLimiting("evidence-view");

// عرض نسخة محفوظة من الدليل (مع فك تشفير AES-256-GCM، التحقق من SHA-256، وعزل Sandbox).
app.MapGet(
    "/evidence-revisions/{id:guid}/view",
    async (
        Guid id,
        ClaimsPrincipal currentUser,
        HttpContext httpContext,
        AccpDbContext dbContext,
        IWebHostEnvironment environment,
        CaseAuthorizationService authorizationService,
        IAuditService auditService,
        IDataEncryptionService encryptionService) =>
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
                item.OriginalFileName,
                item.Sha256Hash,
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

        byte[] decryptedBytes;
        try
        {
            var storedBytes = await File.ReadAllBytesAsync(fullFilePath, httpContext.RequestAborted);
            decryptedBytes = encryptionService.DecryptBytes(
                storedBytes,
                AesGcmDataEncryptionService.EvidenceFilePurpose);
        }
        catch (CryptographicException)
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.AccessDenied,
                currentUser,
                revision.CyberCaseId,
                nameof(EvidenceRevisionEntity),
                revision.Id,
                "فشل فك تشفير نسخة الدليل أو اكتشاف تلاعب محتمل ببيانات التخزين.",
                false,
                "AES-GCM authentication failed.");

            return Results.StatusCode(StatusCodes.Status500InternalServerError);
        }

        if (!VerifySha256ConstantTime(decryptedBytes, revision.Sha256Hash))
        {
            await WriteEvidenceAuditAsync(
                auditService,
                dbContext,
                AuditAction.AccessDenied,
                currentUser,
                revision.CyberCaseId,
                nameof(EvidenceRevisionEntity),
                revision.Id,
                "فشل التحقق من بصمة SHA-256 لنسخة الدليل؛ تم منع العرض لاحتمال التلاعب.",
                false,
                "SHA-256 integrity mismatch.");

            return Results.StatusCode(StatusCodes.Status500InternalServerError);
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
                "تم فتح نسخة محفوظة من الدليل بعد التحقق من سلامتها.",
                true);
        }

        ApplyEvidenceSandboxHeaders(httpContext);

        bool isPdf = string.Equals(revision.ContentType, "application/pdf", StringComparison.OrdinalIgnoreCase);
        string? downloadName = isPdf ? SanitizeDownloadFileName(revision.OriginalFileName, "evidence-revision.pdf") : null;

        return Results.File(
            decryptedBytes,
            revision.ContentType,
            fileDownloadName: downloadName,
            enableRangeProcessing: true);
    })
    .RequireAuthorization()
    .RequireRateLimiting("evidence-view");

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapRazorPages();

app.Run();

static string GetClientIp(HttpContext context)
{
    var address = context.Connection.RemoteIpAddress;
    if (address?.IsIPv4MappedToIPv6 == true)
    {
        address = address.MapToIPv4();
    }

    return address?.ToString() ?? "unknown-client";
}

static RateLimitPartition<string> PostIpPartition(
    HttpContext context,
    string policyName,
    int permitLimit,
    int windowMinutes)
{
    if (!HttpMethods.IsPost(context.Request.Method))
    {
        return RateLimitPartition.GetNoLimiter($"{policyName}-read");
    }

    return RateLimitPartition.GetFixedWindowLimiter(
        $"{policyName}:{GetClientIp(context)}",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = TimeSpan.FromMinutes(windowMinutes),
            QueueLimit = 0,
            AutoReplenishment = true
        });
}

static RateLimitPartition<string> RecoveryPartition(
    HttpContext context,
    int permitLimit) =>
    PostIpPartition(context, "recovery", permitLimit, windowMinutes: 5);

static void ApplyEvidenceSandboxHeaders(HttpContext httpContext)
{
    httpContext.Response.Headers.CacheControl =
        "no-store, no-cache, must-revalidate";
    httpContext.Response.Headers.Pragma = "no-cache";
    httpContext.Response.Headers["X-Content-Type-Options"] = "nosniff";
    httpContext.Response.Headers["X-Frame-Options"] = "DENY";
    httpContext.Response.Headers["Referrer-Policy"] = "no-referrer";
    httpContext.Response.Headers["Content-Security-Policy"] =
        "default-src 'none'; sandbox";
}

static bool VerifySha256ConstantTime(byte[] content, string? expectedHex)
{
    if (string.IsNullOrWhiteSpace(expectedHex))
    {
        return false;
    }

    var actualHex = Convert.ToHexString(SHA256.HashData(content));
    var actualBytes = Encoding.ASCII.GetBytes(actualHex.ToUpperInvariant());
    var expectedBytes = Encoding.ASCII.GetBytes(expectedHex.Trim().ToUpperInvariant());

    return actualBytes.Length == expectedBytes.Length &&
           CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes);
}

static string SanitizeDownloadFileName(string? originalName, string fallback)
{
    var fileName = Path.GetFileName(originalName ?? string.Empty).Trim();
    if (string.IsNullOrWhiteSpace(fileName) || fileName.Any(char.IsControl))
    {
        return fallback;
    }

    return fileName;
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