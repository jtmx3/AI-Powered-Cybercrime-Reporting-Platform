using ACCP.Application.Cases;
using ACCP.Application.Notifications;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using ACCP.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace ACCP.Tests;

public sealed class CaseReopeningTests : IAsyncLifetime
{
    private readonly SqliteConnection connection =
        new("Data Source=:memory:");

    private TestContext db = null!;
    private ApplicationUser admin = null!;
    private ApplicationUser owner = null!;
    private ApplicationUser target = null!;
    private ApplicationUser reporter = null!;
    private CyberCase item = null!;
    private CaseReopeningService service = null!;
    private Guid adminRoleId;

    private const string Reason =
        "Documented reason to reopen this case";

    public async Task InitializeAsync()
    {
        await connection.OpenAsync();

        db = new TestContext(
            new DbContextOptionsBuilder<AccpDbContext>()
                .UseSqlite(connection)
                .Options);

        await db.Database.EnsureCreatedAsync();

        admin = User("admin");
        owner = User("owner");
        target = User("target");
        reporter = User("reporter");

        db.Users.AddRange(admin, owner, target, reporter);

        var adminRole = new IdentityRole<Guid>(IdentityRoles.Admin)
        {
            Id = Guid.NewGuid()
        };

        var officerRole = new IdentityRole<Guid>(IdentityRoles.Officer)
        {
            Id = Guid.NewGuid()
        };

        adminRoleId = adminRole.Id;

        db.Roles.AddRange(adminRole, officerRole);

        db.UserRoles.AddRange(
            new IdentityUserRole<Guid>
            {
                UserId = admin.Id,
                RoleId = adminRole.Id
            },
            new IdentityUserRole<Guid>
            {
                UserId = owner.Id,
                RoleId = officerRole.Id
            },
            new IdentityUserRole<Guid>
            {
                UserId = target.Id,
                RoleId = officerRole.Id
            });

        item = new CyberCase
        {
            CaseNumber = "SYNTHETIC-REOPEN",
            Title = "Synthetic case",
            Description = "Synthetic",
            IncidentType = "Other",
            Path = CasePath.FormalReport,
            Status = CaseStatus.Closed,
            ReporterId = reporter.Id,
            AssignedOfficerId = owner.Id,
            AssignedOfficerEmail = owner.Email,
            AssignedAtUtc = DateTime.UtcNow.AddDays(-1)
        };

        db.CyberCases.Add(item);

        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        service = CreateService();
    }

    public async Task DisposeAsync()
    {
        await db.DisposeAsync();
        await connection.DisposeAsync();
    }

    private static ApplicationUser User(string name) => new()
    {
        Id = Guid.NewGuid(),
        UserName = name,
        Email = name + "@example.test",
        IsActive = true
    };

    private CaseReopeningService CreateService(
        INotificationService? notifications = null) =>
        new(
            db,
            new AuditService(db),
            notifications ?? new NotificationService(db));

    private async Task<CaseReopeningSnapshot> SnapshotAsync()
    {
        var current = await db.CyberCases
            .AsNoTracking()
            .SingleAsync();

        return new CaseReopeningSnapshot(
            current.Id,
            current.CaseNumber,
            current.Status,
            current.AssignedOfficerId,
            current.AssignedAtUtc,
            await db.CaseStatusHistories.CountAsync());
    }

    private async Task AssertNoEffectsAsync(
        CaseStatus status = CaseStatus.Closed)
    {
        Assert.Equal(
            status,
            (await db.CyberCases.AsNoTracking().SingleAsync()).Status);

        Assert.Empty(
            await db.CaseStatusHistories.AsNoTracking().ToListAsync());

        Assert.Empty(
            await db.AuditLogs.AsNoTracking().ToListAsync());

        Assert.Empty(
            await db.UserNotifications.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(CaseStatus.Closed)]
    [InlineData(CaseStatus.Resolved)]
    public async Task ReopensTerminalCaseWithReasonAndNotifiesOwnerAndReporter(
        CaseStatus status)
    {
        await db.CyberCases.ExecuteUpdateAsync(
            setters => setters.SetProperty(c => c.Status, status));

        var expected = await SnapshotAsync();

        Assert.True(
            await service.ReopenAsync(
                expected,
                owner.Id,
                admin.Id,
                "  " + Reason + "  "));

        var current = await db.CyberCases
            .AsNoTracking()
            .SingleAsync();

        Assert.Equal(CaseStatus.InProgress, current.Status);
        Assert.Equal(owner.Id, current.AssignedOfficerId);
        Assert.Equal(expected.AssignedAtUtc, current.AssignedAtUtc);

        var history = await db.CaseStatusHistories.SingleAsync();

        Assert.Equal(status, history.OldStatus);
        Assert.Equal(CaseStatus.InProgress, history.NewStatus);
        Assert.Equal(admin.Id, history.ChangedByUserId);
        Assert.Equal(Reason, history.Reason);

        Assert.Single(await db.AuditLogs.ToListAsync());

        var recipients = await db.UserNotifications
            .Select(n => n.RecipientUserId)
            .ToListAsync();

        Assert.Equal(2, recipients.Count);
        Assert.Contains(owner.Id, recipients);
        Assert.Contains(reporter.Id, recipients);

        Assert.False(
            await service.ReopenAsync(
                expected,
                owner.Id,
                admin.Id,
                Reason));

        Assert.Equal(1, await db.CaseStatusHistories.CountAsync());
        Assert.Equal(2, await db.UserNotifications.CountAsync());
    }

    [Fact]
    public async Task RejectsNonAdminAndDisabledTarget()
    {
        var expected = await SnapshotAsync();

        Assert.False(
            await service.ReopenAsync(
                expected,
                target.Id,
                owner.Id,
                Reason));

        await db.Users
            .Where(u => u.Id == target.Id)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(u => u.IsActive, false));

        Assert.False(
            await service.ReopenAsync(
                expected,
                target.Id,
                admin.Id,
                Reason));

        await AssertNoEffectsAsync();
    }

    [Fact]
    public async Task RejectsOpenOrPrivateCase()
    {
        await db.CyberCases.ExecuteUpdateAsync(
            setters => setters.SetProperty(
                c => c.Status,
                CaseStatus.InProgress));

        Assert.False(
            await service.ReopenAsync(
                await SnapshotAsync(),
                owner.Id,
                admin.Id,
                Reason));

        await AssertNoEffectsAsync(CaseStatus.InProgress);

        await db.CyberCases.ExecuteUpdateAsync(
            setters => setters
                .SetProperty(c => c.Status, CaseStatus.Closed)
                .SetProperty(c => c.Path, (CasePath)1));

        Assert.False(
            await service.ReopenAsync(
                await SnapshotAsync(),
                owner.Id,
                admin.Id,
                Reason));

        await AssertNoEffectsAsync();
    }

    [Fact]
    public async Task RejectsInvalidReasonAndChangedAssignment()
    {
        var expected = await SnapshotAsync();

        foreach (var reason in new[]
        {
            "",
            "   ",
            "short",
            new string('x', 1001)
        })
        {
            Assert.False(
                await service.ReopenAsync(
                    expected,
                    owner.Id,
                    admin.Id,
                    reason));
        }

        await db.CyberCases.ExecuteUpdateAsync(
            setters => setters.SetProperty(
                c => c.AssignedOfficerId,
                (Guid?)target.Id));

        Assert.False(
            await service.ReopenAsync(
                expected,
                owner.Id,
                admin.Id,
                Reason));

        await AssertNoEffectsAsync();
    }

    [Fact]
    public async Task RejectsTargetWithAdminRoleAndAdminWhoseRoleWasRemoved()
    {
        db.UserRoles.Add(new IdentityUserRole<Guid>
        {
            UserId = target.Id,
            RoleId = adminRoleId
        });

        await db.SaveChangesAsync();

        var expected = await SnapshotAsync();

        Assert.False(
            await service.ReopenAsync(
                expected,
                target.Id,
                admin.Id,
                Reason));

        await db.UserRoles
            .Where(r => r.UserId == admin.Id)
            .ExecuteDeleteAsync();

        Assert.False(
            await service.ReopenAsync(
                expected,
                owner.Id,
                admin.Id,
                Reason));

        await AssertNoEffectsAsync();
    }

    [Fact]
    public async Task ChangedHistoryInvalidatesSnapshotEvenWhenStatusIsClosedAgain()
    {
        var expected = await SnapshotAsync();

        db.CaseStatusHistories.Add(new CaseStatusHistory
        {
            CyberCaseId = item.Id,
            OldStatus = CaseStatus.InProgress,
            NewStatus = CaseStatus.Closed,
            ChangedByUserId = owner.Id,
            ChangedByEmail = owner.Email!,
            Reason = Reason
        });

        await db.SaveChangesAsync();

        Assert.False(
            await service.ReopenAsync(
                expected,
                owner.Id,
                admin.Id,
                Reason));

        Assert.Equal(
            CaseStatus.Closed,
            (await db.CyberCases.AsNoTracking().SingleAsync()).Status);

        Assert.Equal(1, await db.CaseStatusHistories.CountAsync());
        Assert.Empty(await db.UserNotifications.ToListAsync());
    }

    [Fact]
    public async Task ChangedOwnerRevokesDuplicateGrantsAndCancelsPendingRequest()
    {
        db.CaseCollaborators.AddRange(
            Grant(owner),
            Grant(target),
            Grant(reporter));

        db.CaseStaffRequests.Add(new CaseStaffRequest
        {
            CyberCaseId = item.Id,
            RequestedByOfficerId = owner.Id,
            RequestedByOfficerEmail = owner.Email!,
            Reason = Reason,
            Status = CaseStaffRequestStatus.Pending
        });

        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        Assert.True(
            await service.ReopenAsync(
                await SnapshotAsync(),
                target.Id,
                admin.Id,
                Reason));

        var current = await db.CyberCases
            .AsNoTracking()
            .SingleAsync();

        Assert.Equal(target.Id, current.AssignedOfficerId);

        Assert.False(
            (await db.CaseCollaborators.SingleAsync(
                c => c.OfficerId == owner.Id)).IsActive);

        Assert.False(
            (await db.CaseCollaborators.SingleAsync(
                c => c.OfficerId == target.Id)).IsActive);

        Assert.True(
            (await db.CaseCollaborators.SingleAsync(
                c => c.OfficerId == reporter.Id)).IsActive);

        Assert.Equal(
            CaseStaffRequestStatus.Cancelled,
            (await db.CaseStaffRequests.SingleAsync()).Status);

        Assert.All(
            await db.UserNotifications
                .Where(n => n.RecipientUserId == owner.Id)
                .ToListAsync(),
            notification => Assert.Null(notification.CyberCaseId));
    }

    [Fact]
    public async Task NotificationFailureRollsBackStatusHistoryAuditAndNotification()
    {
        db.CaseCollaborators.AddRange(
            Grant(owner),
            Grant(target));

        db.CaseStaffRequests.Add(new CaseStaffRequest
        {
            CyberCaseId = item.Id,
            RequestedByOfficerId = owner.Id,
            RequestedByOfficerEmail = owner.Email!,
            Reason = Reason,
            Status = CaseStaffRequestStatus.Pending
        });

        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        var expected = await SnapshotAsync();

        var failing = CreateService(
            new FailingNotifications(new NotificationService(db)));

        await Assert.ThrowsAsync<InjectedFailure>(
            () => failing.ReopenAsync(
                expected,
                target.Id,
                admin.Id,
                Reason));

        await AssertNoEffectsAsync();

        Assert.Equal(
            owner.Id,
            (await db.CyberCases.AsNoTracking().SingleAsync())
                .AssignedOfficerId);

        Assert.All(
            await db.CaseCollaborators.AsNoTracking().ToListAsync(),
            entry => Assert.True(entry.IsActive));

        Assert.Equal(
            CaseStaffRequestStatus.Pending,
            (await db.CaseStaffRequests.AsNoTracking().SingleAsync())
                .Status);
    }

    private CaseCollaborator Grant(ApplicationUser user) => new()
    {
        CyberCaseId = item.Id,
        OfficerId = user.Id,
        OfficerEmail = user.Email!,
        AddedByAdminId = admin.Id,
        AddedByAdminEmail = admin.Email!,
        SourceRequestId = Guid.NewGuid(),
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

        public Task<bool> MarkAsReadAsync(Guid id, Guid user) =>
            inner.MarkAsReadAsync(id, user);

        public Task<int> MarkAllAsReadAsync(Guid id) =>
            inner.MarkAllAsReadAsync(id);
    }

    private sealed class TestContext(
        DbContextOptions<AccpDbContext> options) : AccpDbContext(options)
    {
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<CaseCollaborator>()
                .Property(c => c.RowVersion)
                .IsRequired()
                .ValueGeneratedNever();

            builder.Entity<CaseStaffRequest>()
                .Property(c => c.RowVersion)
                .IsRequired()
                .ValueGeneratedNever();
        }
    }
}