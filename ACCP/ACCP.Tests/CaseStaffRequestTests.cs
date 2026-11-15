using ACCP.Application.Notifications;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using ACCP.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ACCP.Tests;

public sealed class CaseStaffRequestTests : IAsyncLifetime
{
    private readonly SqliteConnection connection =
        new("Data Source=:memory:");

    private TestContext db = null!;
    private UserManager<ApplicationUser> users = null!;
    private ServiceProvider provider = null!;
    private CaseStaffRequestService service = null!;

    private ApplicationUser admin = null!;
    private ApplicationUser owner = null!;
    private ApplicationUser target = null!;
    private ApplicationUser participant = null!;

    private CyberCase caseItem = null!;
    private CaseStaffRequest request = null!;

    private Guid adminRoleId;
    private Guid officerRoleId;

    public async Task InitializeAsync()
    {
        await connection.OpenAsync();

        db = new TestContext(
            new DbContextOptionsBuilder<AccpDbContext>()
                .UseSqlite(connection)
                .Options);

        await db.Database.EnsureCreatedAsync();

        admin = NewUser("admin");
        owner = NewUser("owner");
        target = NewUser("target");
        participant = NewUser("participant");

        db.Users.AddRange(admin, owner, target, participant);

        var adminRole = new IdentityRole<Guid>(IdentityRoles.Admin)
        {
            Id = Guid.NewGuid()
        };

        var officerRole = new IdentityRole<Guid>(IdentityRoles.Officer)
        {
            Id = Guid.NewGuid()
        };

        adminRoleId = adminRole.Id;
        officerRoleId = officerRole.Id;

        db.Roles.AddRange(adminRole, officerRole);

        AddRole(admin.Id, adminRoleId);
        AddRole(owner.Id, officerRoleId);
        AddRole(target.Id, officerRoleId);
        AddRole(participant.Id, officerRoleId);

        caseItem = new CyberCase
        {
            CaseNumber = "SYNTHETIC-STAFF-REQUEST",
            Title = "Private complaint title",
            Description = "Private complaint description",
            IncidentType = "Other",
            Path = CasePath.FormalReport,
            Status = CaseStatus.InProgress,
            AssignedOfficerId = owner.Id,
            AssignedOfficerEmail = owner.Email,
            AssignedAtUtc = DateTime.UtcNow.AddDays(-1),
            ReporterId = Guid.NewGuid(),
            IsReporterIdentityDisclosed = true,
            DisclosedReporterName = "Private reporter name",
            DisclosedReporterEmail = "private@example.test"
        };

        request = new CaseStaffRequest
        {
            CyberCaseId = caseItem.Id,
            RequestedByOfficerId = owner.Id,
            RequestedByOfficerEmail = owner.Email!,
            RequestType = CaseStaffRequestType.TransferAssignment,
            Reason = "Synthetic documented transfer request",
            Status = CaseStaffRequestStatus.Pending
        };

        db.CyberCases.Add(caseItem);
        db.CaseStaffRequests.Add(request);

        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        provider = new ServiceCollection().BuildServiceProvider();

        users = new UserManager<ApplicationUser>(
            new UserStore<
                ApplicationUser,
                IdentityRole<Guid>,
                AccpDbContext,
                Guid>(db),
            Options.Create(new IdentityOptions()),
            new PasswordHasher<ApplicationUser>(),
            Array.Empty<IUserValidator<ApplicationUser>>(),
            Array.Empty<IPasswordValidator<ApplicationUser>>(),
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            provider,
            NullLogger<UserManager<ApplicationUser>>.Instance);

        service = CreateService(new NotificationService(db));
    }

    public async Task DisposeAsync()
    {
        users.Dispose();
        await provider.DisposeAsync();
        await db.DisposeAsync();
        await connection.DisposeAsync();
    }

    [Fact]
    public async Task Transfer_RemovesOldAndNewOwnerParticipation_KeepsOthers()
    {
        db.CaseCollaborators.AddRange(
            Collaboration(owner),
            Collaboration(target),
            Collaboration(participant));

        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        Assert.True(await ApproveAsync());

        db.ChangeTracker.Clear();

        var persisted = await db.CyberCases.SingleAsync();
        Assert.Equal(target.Id, persisted.AssignedOfficerId);
        Assert.Equal(CaseStatus.InProgress, persisted.Status);

        var collaborations = await db.CaseCollaborators.ToListAsync();

        Assert.False(collaborations.Single(
            item => item.OfficerId == owner.Id).IsActive);

        Assert.False(collaborations.Single(
            item => item.OfficerId == target.Id).IsActive);

        Assert.True(collaborations.Single(
            item => item.OfficerId == participant.Id).IsActive);

        Assert.Equal(
            CaseStaffRequestStatus.Approved,
            (await db.CaseStaffRequests.SingleAsync()).Status);

        Assert.NotEmpty(await db.AuditLogs.ToListAsync());
        Assert.NotEmpty(await db.UserNotifications.ToListAsync());
    }

    [Theory]
    [InlineData("inactive")]
    [InlineData("locked")]
    [InlineData("admin")]
    [InlineData("no-officer-role")]
    public async Task IneligibleTarget_IsRejectedWithoutSideEffects(
        string condition)
    {
        var account = await db.Users.SingleAsync(
            item => item.Id == target.Id);

        switch (condition)
        {
            case "inactive":
                account.IsActive = false;
                break;

            case "locked":
                account.LockoutEnabled = true;
                account.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1);
                break;

            case "admin":
                AddRole(target.Id, adminRoleId);
                break;

            case "no-officer-role":
                var membership = await db.UserRoles.SingleAsync(item =>
                    item.UserId == target.Id &&
                    item.RoleId == officerRoleId);

                db.UserRoles.Remove(membership);
                break;
        }

        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        Assert.False(await ApproveAsync());

        await AssertUnchangedAsync();
    }

    [Theory]
    [InlineData(CaseStatus.Resolved)]
    [InlineData(CaseStatus.Closed)]
    public async Task FinishedCase_CannotBeTransferred(CaseStatus status)
    {
        var item = await db.CyberCases.SingleAsync();
        item.Status = status;

        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        Assert.False(await ApproveAsync());

        await AssertUnchangedAsync();
    }

    [Fact]
    public async Task RepeatingApproval_DoesNotDuplicateEffects()
    {
        Assert.True(await ApproveAsync());

        var auditCount = await db.AuditLogs.CountAsync();
        var notificationCount = await db.UserNotifications.CountAsync();

        db.ChangeTracker.Clear();

        Assert.False(await ApproveAsync());

        Assert.Equal(auditCount, await db.AuditLogs.CountAsync());
        Assert.Equal(
            notificationCount,
            await db.UserNotifications.CountAsync());
    }

    [Fact]
    public async Task ChangedOwner_RejectsOldPendingRequest()
    {
        var item = await db.CyberCases.SingleAsync();
        item.AssignedOfficerId = participant.Id;
        item.AssignedOfficerEmail = participant.Email;

        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        Assert.False(await ApproveAsync());

        Assert.Equal(
            participant.Id,
            (await db.CyberCases.AsNoTracking().SingleAsync())
                .AssignedOfficerId);

        Assert.Equal(
            CaseStaffRequestStatus.Pending,
            (await db.CaseStaffRequests.AsNoTracking().SingleAsync())
                .Status);

        Assert.Empty(await db.AuditLogs.ToListAsync());
        Assert.Empty(await db.UserNotifications.ToListAsync());
    }

    [Fact]
    public async Task AdminRead_ReturnsMetadataWithoutComplaintContent()
    {
        var rows = await service.GetForAdminAsync();

        var row = Assert.Single(rows);

        Assert.Equal(caseItem.CaseNumber, row.CyberCase.CaseNumber);
        Assert.Equal(owner.Id, row.CyberCase.AssignedOfficerId);

        Assert.True(string.IsNullOrEmpty(row.CyberCase.Title));
        Assert.True(string.IsNullOrEmpty(row.CyberCase.Description));
        Assert.Null(row.CyberCase.ReporterId);
        Assert.Null(row.CyberCase.DisclosedReporterName);
        Assert.Null(row.CyberCase.DisclosedReporterEmail);
    }

    [Fact]
    public async Task NotificationFailure_RollsBackTransferAndParticipation()
    {
        db.CaseCollaborators.Add(Collaboration(owner));
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        service = CreateService(
            new FailingNotifications(new NotificationService(db)));

        await Assert.ThrowsAsync<InjectedFailure>(
            async () => { await ApproveAsync(); });

        await AssertUnchangedAsync();

        var collaboration = await db.CaseCollaborators
            .AsNoTracking()
            .SingleAsync();

        Assert.True(collaboration.IsActive);
        Assert.Null(collaboration.RemovedAtUtc);
    }

    private Task<bool> ApproveAsync() =>
        service.ApproveForAdminAsync(
            request.Id,
            target.Id,
            admin.Id,
            admin.Email!,
            "Synthetic administrative approval");

    private CaseStaffRequestService CreateService(
        INotificationService notifications) =>
        new(db, users, notifications, new AuditService(db));

    private async Task AssertUnchangedAsync()
    {
        db.ChangeTracker.Clear();

        Assert.Equal(
            owner.Id,
            (await db.CyberCases.AsNoTracking().SingleAsync())
                .AssignedOfficerId);

        Assert.Equal(
            CaseStaffRequestStatus.Pending,
            (await db.CaseStaffRequests.AsNoTracking().SingleAsync())
                .Status);

        Assert.Empty(await db.AuditLogs.ToListAsync());
        Assert.Empty(await db.UserNotifications.ToListAsync());
    }

    private void AddRole(Guid userId, Guid roleId) =>
        db.UserRoles.Add(new IdentityUserRole<Guid>
        {
            UserId = userId,
            RoleId = roleId
        });

    private static ApplicationUser NewUser(string name) =>
        new()
        {
            Id = Guid.NewGuid(),
            UserName = name,
            NormalizedUserName = name.ToUpperInvariant(),
            Email = $"{name}@example.test",
            NormalizedEmail = $"{name}@example.test".ToUpperInvariant(),
            FullName = name,
            IsActive = true,
            SecurityStamp = Guid.NewGuid().ToString("N")
        };

    private CaseCollaborator Collaboration(ApplicationUser user) =>
        new()
        {
            CyberCaseId = caseItem.Id,
            OfficerId = user.Id,
            OfficerEmail = user.Email!,
            SourceRequestId = Guid.NewGuid(),
            AddedByAdminId = admin.Id,
            AddedByAdminEmail = admin.Email!,
            IsActive = true
        };

    private sealed class InjectedFailure : Exception
    {
    }

    private sealed class FailingNotifications(
        INotificationService inner) : INotificationService
    {
        public async Task<UserNotification> CreateAsync(
            Guid recipientUserId,
            Guid? cyberCaseId,
            NotificationType type,
            string title,
            string message)
        {
            await inner.CreateAsync(
                recipientUserId,
                cyberCaseId,
                type,
                title,
                message);

            throw new InjectedFailure();
        }

        public Task<List<UserNotification>> GetForUserAsync(Guid id) =>
            inner.GetForUserAsync(id);

        public Task<int> GetUnreadCountAsync(Guid id) =>
            inner.GetUnreadCountAsync(id);

        public Task<bool> MarkAsReadAsync(Guid id, Guid userId) =>
            inner.MarkAsReadAsync(id, userId);

        public Task<int> MarkAllAsReadAsync(Guid userId) =>
            inner.MarkAllAsReadAsync(userId);
    }

    private sealed class TestContext(
        DbContextOptions<AccpDbContext> options) : AccpDbContext(options)
    {
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // SQLite لا يولّد SQL Server rowversion.
            builder.Entity<CaseCollaborator>()
                .Property(item => item.RowVersion)
                .IsRequired()
                .ValueGeneratedNever();

            builder.Entity<CaseStaffRequest>()
                .Property(item => item.RowVersion)
                .IsRequired()
                .ValueGeneratedNever();
        }
    }
}