using ACCP.Application.Auditing;
using ACCP.Application.Notifications;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using ACCP.Infrastructure.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace ACCP.Tests;

// Each test gets its own in-memory database and synthetic users.
public sealed class CaseServiceTests : IAsyncLifetime
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private AccpDbContext _db = null!;
    private AuditService _audit = null!;
    private NotificationService _notifications = null!;
    private CaseService _service = null!;
    private ApplicationUser _reporter = null!;
    private ApplicationUser _owner = null!;
    private ApplicationUser _collaborator = null!;
    private ApplicationUser _formerCollaborator = null!;
    private Guid _caseId;

    public async Task InitializeAsync()
    {
        await _connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AccpDbContext>()
            .UseSqlite(_connection).Options;
        _db = new SqliteCaseTestContext(options);
        await _db.Database.EnsureCreatedAsync();

        _reporter = NewUser("reporter");
        _reporter.FullName = "Synthetic Reporter";
        _owner = NewUser("owner");
        _collaborator = NewUser("collaborator");
        _formerCollaborator = NewUser("former");
        _db.Users.AddRange(_reporter, _owner, _collaborator, _formerCollaborator);

        var item = NewCase();
        item.ReporterId = _reporter.Id;
        item.AssignedOfficerId = _owner.Id;
        item.AssignedOfficerEmail = _owner.Email;
        item.Status = CaseStatus.Assigned;
        _caseId = item.Id;
        _db.CyberCases.Add(item);
        _db.CaseCollaborators.Add(NewCollaborator(_collaborator, true));
        _db.CaseCollaborators.Add(NewCollaborator(_formerCollaborator, false));
        await _db.SaveChangesAsync();
        _db.ChangeTracker.Clear();

        _audit = new AuditService(_db);
        _notifications = new NotificationService(_db);
        _service = new CaseService(_db, _audit, _notifications);
    }

    public async Task DisposeAsync()
    {
        if (_db is not null)
        {
            await _db.DisposeAsync();
        }
        await _connection.DisposeAsync();
    }

    [Fact]
    public async Task ActiveCollaborator_Note_SavesLinkedAuditWithoutNoteContent()
    {
        const string content = "Synthetic private note content";
        var note = await _service.AddInternalNoteForOfficerAsync(
            _caseId, content, _collaborator.Id, _collaborator.Email!);

        Assert.NotNull(note);
        Assert.True(await _db.CaseNotes.AnyAsync(item => item.Id == note.Id));
        var log = await _db.AuditLogs.SingleAsync();
        Assert.Equal(AuditAction.InternalNoteAdded, log.Action);
        Assert.Equal(note.Id, log.EntityId);
        Assert.Equal(_caseId, log.CyberCaseId);
        Assert.Equal(_collaborator.Id, log.ActorUserId);
        Assert.Equal("OFFICER", log.ActorRole);
        Assert.DoesNotContain(content, log.Description);
    }

    [Fact]
    public async Task InactiveCollaborator_CannotAddNotesOrSendMessages()
    {
        var before = await ReadCountsAsync();
        Assert.Null(await _service.AddInternalNoteForOfficerAsync(
            _caseId, "Denied note", _formerCollaborator.Id, _formerCollaborator.Email!));
        Assert.Null(await _service.SendMessageByOfficerAsync(
            _caseId, "Denied message", _formerCollaborator.Id, _formerCollaborator.Email!));
        Assert.Equal(before, await ReadCountsAsync());
    }

    [Fact]
    public async Task ReporterMessage_AuditsAndNotifiesOnlyDistinctActiveStaff()
    {
        // Listing the owner as a collaborator must not duplicate the notification.
        _db.CaseCollaborators.Add(NewCollaborator(_owner, true));
        await _db.SaveChangesAsync();
        _db.ChangeTracker.Clear();

        var message = await _service.SendMessageByReporterAsync(
            _caseId, "Synthetic reporter message", _reporter.Id, _reporter.Email!);

        Assert.NotNull(message);
        var recipients = await _db.UserNotifications
            .Select(notification => notification.RecipientUserId).ToListAsync();
        Assert.Equal(2, recipients.Count);
        Assert.Contains(_owner.Id, recipients);
        Assert.Contains(_collaborator.Id, recipients);
        Assert.DoesNotContain(_formerCollaborator.Id, recipients);
        var log = await _db.AuditLogs.SingleAsync();
        Assert.Equal(AuditAction.CaseMessageSent, log.Action);
        Assert.Equal(message.Id, log.EntityId);
        Assert.Equal(_reporter.Id, log.ActorUserId);
        Assert.Equal("USER", log.ActorRole);
    }

    [Fact]
    public async Task CollaboratorMessage_AuditsAndNotifiesTheReporter()
    {
        var message = await _service.SendMessageByOfficerAsync(
            _caseId, "Synthetic collaborator message", _collaborator.Id, _collaborator.Email!);

        Assert.NotNull(message);
        var notification = await _db.UserNotifications.SingleAsync();
        Assert.Equal(_reporter.Id, notification.RecipientUserId);
        Assert.Equal(NotificationType.NewMessage, notification.Type);
        var log = await _db.AuditLogs.SingleAsync();
        Assert.Equal(AuditAction.CaseMessageSent, log.Action);
        Assert.Equal(message.Id, log.EntityId);
        Assert.Equal(_collaborator.Id, log.ActorUserId);
        Assert.Equal("OFFICER", log.ActorRole);
    }

    [Fact]
    public async Task AnotherUser_CannotDiscloseReporterIdentity()
    {
        var before = await ReadCountsAsync();
        Assert.False(await _service.DiscloseReporterIdentityAsync(
            _caseId, _formerCollaborator.Id));
        var item = await _db.CyberCases.AsNoTracking().SingleAsync();
        Assert.False(item.IsReporterIdentityDisclosed);
        Assert.Null(item.DisclosedReporterEmail);
        Assert.Equal(before, await ReadCountsAsync());
    }

    [Fact]
    public async Task RepeatedReporterConsent_CreatesExactlyOneDisclosureAudit()
    {
        Assert.True(await _service.DiscloseReporterIdentityAsync(_caseId, _reporter.Id));
        Assert.True(await _service.DiscloseReporterIdentityAsync(_caseId, _reporter.Id));

        var item = await _db.CyberCases.AsNoTracking().SingleAsync();
        Assert.True(item.IsReporterIdentityDisclosed);
        Assert.Equal(_reporter.FullName, item.DisclosedReporterName);
        Assert.Equal(_reporter.Email, item.DisclosedReporterEmail);
        Assert.NotNull(item.ReporterIdentityDisclosedAtUtc);
        var log = await _db.AuditLogs.SingleAsync();
        Assert.Equal(AuditAction.ReporterIdentityDisclosed, log.Action);
        Assert.Equal(_reporter.Id, log.ActorUserId);
        Assert.Equal(_caseId, log.EntityId);
    }

    [Fact]
    public async Task FailedMessageNotification_RollsBackMessageAuditAndNotification()
    {
        var service = new CaseService(_db, _audit,
            new FailingNotificationService(_notifications));
        var before = await ReadCountsAsync();

        await Assert.ThrowsAsync<InjectedFailureException>(() =>
            service.SendMessageByOfficerAsync(
                _caseId, "Must roll back", _collaborator.Id, _collaborator.Email!));

        Assert.Equal(before, await ReadCountsAsync());
        Assert.False(_db.ChangeTracker.HasChanges());
    }

    [Fact]
    public async Task FailedNoteAudit_RollsBackTheNoteAndAudit()
    {
        var service = new CaseService(_db,
            new FailingAuditService(_audit), _notifications);
        var before = await ReadCountsAsync();

        await Assert.ThrowsAsync<InjectedFailureException>(() =>
            service.AddInternalNoteForOfficerAsync(
                _caseId, "Must roll back", _collaborator.Id, _collaborator.Email!));

        Assert.Equal(before, await ReadCountsAsync());
        Assert.False(_db.ChangeTracker.HasChanges());
    }

    [Fact]
    public async Task CreateCase_PersistsCaseAndMatchingAudit()
    {
        var item = await _service.CreateForReporterAsync(NewCase(), _reporter.Id);

        Assert.True(await _db.CyberCases.AnyAsync(current =>
            current.Id == item.Id && current.ReporterId == _reporter.Id));
        var log = await _db.AuditLogs.SingleAsync();
        Assert.Equal(AuditAction.CaseCreated, log.Action);
        Assert.Equal(item.Id, log.EntityId);
        Assert.Equal(item.Id, log.CyberCaseId);
        Assert.Equal(_reporter.Id, log.ActorUserId);
    }

    [Fact]
    public async Task CreatedCases_GetDistinctNumbersWithinStorageLimit()
    {
        var first = await _service.CreateForReporterAsync(NewCase(), _reporter.Id);
        var second = await _service.CreateForReporterAsync(NewCase(), _reporter.Id);

        Assert.False(string.IsNullOrWhiteSpace(first.CaseNumber));
        Assert.False(string.IsNullOrWhiteSpace(second.CaseNumber));
        Assert.NotEqual(first.CaseNumber, second.CaseNumber);
        Assert.InRange(first.CaseNumber.Length, 1, 50);
        Assert.InRange(second.CaseNumber.Length, 1, 50);

        var persistedNumbers = await _db.CyberCases.AsNoTracking()
            .Where(item => item.Id == first.Id || item.Id == second.Id)
            .Select(item => item.CaseNumber).ToListAsync();
        Assert.Equal(2, persistedNumbers.Count);
        Assert.Contains(first.CaseNumber, persistedNumbers);
        Assert.Contains(second.CaseNumber, persistedNumbers);
    }

    [Fact]
    public async Task DuplicateCaseNumber_RejectsCreationWithoutPartialEffects()
    {
        var first = NewCase();
        first.CaseNumber = "ACCP-SYNTHETIC-DUPLICATE";
        await _service.CreateForReporterAsync(first, _reporter.Id);
        var before = await ReadCountsAsync();

        var duplicate = NewCase();
        duplicate.CaseNumber = first.CaseNumber;
        var failure = await Assert.ThrowsAsync<DbUpdateException>(() =>
            _service.CreateForReporterAsync(duplicate, _reporter.Id));

        // SQLite's extended code 2067 identifies a UNIQUE constraint violation.
        var databaseFailure = Assert.IsType<SqliteException>(failure.InnerException);
        Assert.Equal(2067, databaseFailure.SqliteExtendedErrorCode);
        Assert.Equal(before, await ReadCountsAsync());
        Assert.False(_db.ChangeTracker.HasChanges());
        Assert.False(await _db.CyberCases.AnyAsync(item => item.Id == duplicate.Id));
        Assert.Equal(1, await _db.CyberCases.CountAsync(item =>
            item.CaseNumber == first.CaseNumber));
    }

    [Fact]
    public async Task FailedCreationAudit_RollsBackTheCaseAndAudit()
    {
        var service = new CaseService(_db,
            new FailingAuditService(_audit), _notifications);
        var before = await ReadCountsAsync();

        await Assert.ThrowsAsync<InjectedFailureException>(() =>
            service.CreateForReporterAsync(NewCase(), _reporter.Id));

        Assert.Equal(before, await ReadCountsAsync());
        Assert.False(_db.ChangeTracker.HasChanges());
    }

    [Fact]
    public async Task StatusChange_SavesStateHistoryAuditAndNotification()
    {
        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.InProgress, _owner.Id, _owner.Email!));

        var item = await _db.CyberCases.AsNoTracking().SingleAsync();
        Assert.Equal(CaseStatus.InProgress, item.Status);
        var history = await _db.CaseStatusHistories.SingleAsync();
        Assert.Equal(CaseStatus.Assigned, history.OldStatus);
        Assert.Equal(CaseStatus.InProgress, history.NewStatus);
        Assert.Equal(_owner.Id, history.ChangedByUserId);
        var log = await _db.AuditLogs.SingleAsync();
        Assert.Equal(AuditAction.CaseStatusChanged, log.Action);
        Assert.Equal(_caseId, log.EntityId);
        var notification = await _db.UserNotifications.SingleAsync();
        Assert.Equal(_reporter.Id, notification.RecipientUserId);
        Assert.Equal(NotificationType.CaseStatusChanged, notification.Type);
    }

    [Fact]
    public async Task RepeatedIdenticalStatus_DoesNotDuplicateHistoryAuditOrNotifications()
    {
        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.InProgress, _owner.Id, _owner.Email!));
        var before = await ReadCountsAsync();

        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.InProgress, _owner.Id, _owner.Email!));

        Assert.Equal(before, await ReadCountsAsync());
    }

    [Fact]
    public async Task StatusChange_RejectsCollaboratorsAndUndefinedEnumValues()
    {
        var before = await ReadCountsAsync();
        Assert.False(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.Resolved, _collaborator.Id, _collaborator.Email!));
        Assert.False(await _service.UpdateStatusForOfficerAsync(
            _caseId, (CaseStatus)999, _owner.Id, _owner.Email!));

        var item = await _db.CyberCases.AsNoTracking().SingleAsync();
        Assert.Equal(CaseStatus.Assigned, item.Status);
        Assert.Equal(before, await ReadCountsAsync());
    }

    [Fact]
    public async Task FailedStatusNotification_RollsBackStateHistoryAuditAndNotification()
    {
        var service = new CaseService(_db, _audit,
            new FailingNotificationService(_notifications));
        var before = await ReadCountsAsync();

        await Assert.ThrowsAsync<InjectedFailureException>(() =>
            service.UpdateStatusForOfficerAsync(
                _caseId, CaseStatus.InProgress, _owner.Id, _owner.Email!));

        var item = await _db.CyberCases.AsNoTracking().SingleAsync();
        Assert.Equal(CaseStatus.Assigned, item.Status);
        Assert.Equal(before, await ReadCountsAsync());
        Assert.False(_db.ChangeTracker.HasChanges());
    }

    [Fact]
    public async Task Assignment_KeepsOneOwnerAndDoesNotDuplicateEffectsOnRetry()
    {
        var item = await _service.CreateForReporterAsync(NewCase(), _reporter.Id);
        Assert.True(await _service.AssignToOfficerAsync(item.Id, _owner.Id, _owner.Email!));
        var before = await ReadCountsAsync();

        Assert.True(await _service.AssignToOfficerAsync(item.Id, _owner.Id, _owner.Email!));
        Assert.False(await _service.AssignToOfficerAsync(
            item.Id, _collaborator.Id, _collaborator.Email!));

        var persisted = await _db.CyberCases.AsNoTracking().SingleAsync(current => current.Id == item.Id);
        Assert.Equal(_owner.Id, persisted.AssignedOfficerId);
        Assert.Equal(CaseStatus.Assigned, persisted.Status);
        Assert.Equal(before, await ReadCountsAsync());
        Assert.Equal(1, await _db.AuditLogs.CountAsync(log =>
            log.Action == AuditAction.CaseAssigned && log.EntityId == item.Id));
        Assert.Equal(1, await _db.UserNotifications.CountAsync(notification =>
            notification.CyberCaseId == item.Id && notification.Type == NotificationType.CaseAssigned));
    }

    [Fact]
    public async Task FailedAssignmentNotification_RollsBackClaimHistoryAuditAndNotification()
    {
        var item = await _service.CreateForReporterAsync(NewCase(), _reporter.Id);
        var service = new CaseService(_db, _audit,
            new FailingNotificationService(_notifications));
        var before = await ReadCountsAsync();

        await Assert.ThrowsAsync<InjectedFailureException>(() =>
            service.AssignToOfficerAsync(item.Id, _owner.Id, _owner.Email!));

        var persisted = await _db.CyberCases.AsNoTracking().SingleAsync(current => current.Id == item.Id);
        Assert.Null(persisted.AssignedOfficerId);
        Assert.Null(persisted.AssignedAtUtc);
        Assert.Equal(CaseStatus.New, persisted.Status);
        Assert.Equal(before, await ReadCountsAsync());
        Assert.False(_db.ChangeTracker.HasChanges());
    }

    private static ApplicationUser NewUser(string name) => new()
    {
        Id = Guid.NewGuid(), UserName = name, Email = name + "@example.test"
    };

    private static CyberCase NewCase() => new()
    {
        Title = "Synthetic test case",
        Description = "Synthetic incident description for service tests.",
        IncidentType = "Blackmail"
    };

    private CaseCollaborator NewCollaborator(ApplicationUser user, bool active) => new()
    {
        CyberCaseId = _caseId,
        OfficerId = user.Id,
        OfficerEmail = user.Email!,
        AddedByAdminId = Guid.NewGuid(),
        AddedByAdminEmail = "admin@example.test",
        SourceRequestId = Guid.NewGuid(),
        IsActive = active
    };

    [Fact]
    public async Task StatusChange_RejectsSkippingAssignedToResolved()
    {
        var before = await ReadCountsAsync();

        Assert.False(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.Resolved, _owner.Id, _owner.Email!, "Documented status change reason"));

        Assert.Equal(CaseStatus.Assigned,
            (await _db.CyberCases.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(before, await ReadCountsAsync());
        Assert.False(_db.ChangeTracker.HasChanges());
    }

    [Fact]
    public async Task StatusChange_RejectsBackwardMoveFromInProgress()
    {
        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.InProgress, _owner.Id, _owner.Email!));
        var before = await ReadCountsAsync();

        Assert.False(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.Assigned, _owner.Id, _owner.Email!));

        Assert.Equal(CaseStatus.InProgress,
            (await _db.CyberCases.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(before, await ReadCountsAsync());
        Assert.False(_db.ChangeTracker.HasChanges());
    }

    [Fact]
    public async Task StatusChange_ClosedCaseCannotBeReopenedByOfficer()
    {
        await _db.CyberCases.Where(item => item.Id == _caseId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(item => item.Status, CaseStatus.Closed));
        var before = await ReadCountsAsync();

        Assert.False(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.InProgress, _owner.Id, _owner.Email!));

        Assert.Equal(CaseStatus.Closed,
            (await _db.CyberCases.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(before, await ReadCountsAsync());
        Assert.False(_db.ChangeTracker.HasChanges());
    }

    [Fact]
    public async Task StatusChange_AllowedChainRecordsEveryTransition()
    {
        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.InProgress, _owner.Id, _owner.Email!));
        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.Resolved, _owner.Id, _owner.Email!, "Documented status change reason"));
        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.Closed, _owner.Id, _owner.Email!, "Documented status change reason"));

        Assert.Equal(CaseStatus.Closed,
            (await _db.CyberCases.AsNoTracking().SingleAsync()).Status);
        var history = await _db.CaseStatusHistories.AsNoTracking().ToListAsync();
        Assert.Equal(3, history.Count);
        Assert.Contains(history, item => item.OldStatus == CaseStatus.Assigned &&
            item.NewStatus == CaseStatus.InProgress);
        Assert.Contains(history, item => item.OldStatus == CaseStatus.InProgress &&
            item.NewStatus == CaseStatus.Resolved);
        Assert.Contains(history, item => item.OldStatus == CaseStatus.Resolved &&
            item.NewStatus == CaseStatus.Closed);
        Assert.Equal(3, await _db.AuditLogs.CountAsync(
            item => item.Action == AuditAction.CaseStatusChanged));
        Assert.Equal(3, await _db.UserNotifications.CountAsync(
            item => item.Type == NotificationType.CaseStatusChanged));

        var beforeRetry = await ReadCountsAsync();
        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.Closed, _owner.Id, _owner.Email!, "Documented status change reason"));
        Assert.Equal(beforeRetry, await ReadCountsAsync());
    }

    [Theory]
    [InlineData(CaseStatus.Resolved, null)]
    [InlineData(CaseStatus.Resolved, "   ")]
    [InlineData(CaseStatus.Resolved, "short")]
    [InlineData(CaseStatus.Closed, null)]
    [InlineData(CaseStatus.Closed, "   ")]
    [InlineData(CaseStatus.Closed, "short")]
    public async Task StatusReason_TerminalChangeRejectsMissingOrShortReason(
        CaseStatus target, string? reason)
    {
        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.InProgress, _owner.Id, _owner.Email!));
        var before = await ReadCountsAsync();
        Assert.False(await _service.UpdateStatusForOfficerAsync(
            _caseId, target, _owner.Id, _owner.Email!, reason));
        Assert.Equal(CaseStatus.InProgress,
            (await _db.CyberCases.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(before, await ReadCountsAsync());
        Assert.False(_db.ChangeTracker.HasChanges());
    }

    [Fact]
    public async Task StatusReason_RejectsOverlongReasonWithoutSideEffects()
    {
        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.InProgress, _owner.Id, _owner.Email!));
        var before = await ReadCountsAsync();
        Assert.False(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.Closed, _owner.Id, _owner.Email!, new string('x', 1001)));
        Assert.Equal(CaseStatus.InProgress,
            (await _db.CyberCases.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(before, await ReadCountsAsync());
        Assert.False(_db.ChangeTracker.HasChanges());
    }

    [Theory]
    [InlineData(CaseStatus.Resolved, 10)]
    [InlineData(CaseStatus.Closed, 1000)]
    public async Task StatusReason_SavesTrimmedReasonAndRetryDoesNotReplaceIt(
        CaseStatus target, int length)
    {
        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.InProgress, _owner.Id, _owner.Email!));
        string reason = new string('x', length);
        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, target, _owner.Id, _owner.Email!, "  " + reason + "  "));
        var history = await _db.CaseStatusHistories.AsNoTracking()
            .SingleAsync(item => item.NewStatus == target);
        Assert.Equal(reason, history.Reason);
        var before = await ReadCountsAsync();
        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, target, _owner.Id, _owner.Email!, "A different retry reason"));
        Assert.Equal(before, await ReadCountsAsync());
        Assert.Equal(reason, (await _db.CaseStatusHistories.AsNoTracking()
            .SingleAsync(item => item.Id == history.Id)).Reason);
    }

    [Fact]
    public async Task StatusReason_NotificationFailureRollsBackTerminalChangeAndReason()
    {
        Assert.True(await _service.UpdateStatusForOfficerAsync(
            _caseId, CaseStatus.InProgress, _owner.Id, _owner.Email!));
        var before = await ReadCountsAsync();
        var service = new CaseService(_db, _audit,
            new FailingNotificationService(_notifications));
        await Assert.ThrowsAsync<InjectedFailureException>(() =>
            service.UpdateStatusForOfficerAsync(
                _caseId, CaseStatus.Resolved, _owner.Id, _owner.Email!,
                "A documented resolution reason"));
        Assert.Equal(CaseStatus.InProgress,
            (await _db.CyberCases.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(before, await ReadCountsAsync());
        Assert.False(await _db.CaseStatusHistories.AnyAsync(
            item => item.NewStatus == CaseStatus.Resolved));
        Assert.False(_db.ChangeTracker.HasChanges());
    }

    private async Task<(int Cases, int Notes, int Messages, int History, int Audits, int Notifications)> ReadCountsAsync() =>
        (await _db.CyberCases.CountAsync(),
         await _db.CaseNotes.CountAsync(),
         await _db.CaseMessages.CountAsync(),
         await _db.CaseStatusHistories.CountAsync(),
         await _db.AuditLogs.CountAsync(),
         await _db.UserNotifications.CountAsync());

    private sealed class SqliteCaseTestContext : AccpDbContext
    {
        public SqliteCaseTestContext(DbContextOptions<AccpDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            // Only this test context uses SQLite. SQL Server generates the real rowversion.
            builder.Entity<CaseCollaborator>()
                .Property(item => item.RowVersion).ValueGeneratedNever();
        }
    }

    private sealed class InjectedFailureException : Exception { }

    // Deliberately fail AFTER the real save to prove the transaction rolls it back.
    private sealed class FailingNotificationService : INotificationService
    {
        private readonly INotificationService _inner;
        public FailingNotificationService(INotificationService inner) => _inner = inner;

        public async Task<UserNotification> CreateAsync(Guid recipientUserId, Guid? cyberCaseId,
            NotificationType type, string title, string message)
        {
            await _inner.CreateAsync(recipientUserId, cyberCaseId, type, title, message);
            throw new InjectedFailureException();
        }

        public Task<List<UserNotification>> GetForUserAsync(Guid id) => _inner.GetForUserAsync(id);
        public Task<int> GetUnreadCountAsync(Guid id) => _inner.GetUnreadCountAsync(id);
        public Task<bool> MarkAsReadAsync(Guid id, Guid user) => _inner.MarkAsReadAsync(id, user);
        public Task<int> MarkAllAsReadAsync(Guid user) => _inner.MarkAllAsReadAsync(user);
    }

    private sealed class FailingAuditService : IAuditService
    {
        private readonly IAuditService _inner;
        public FailingAuditService(IAuditService inner) => _inner = inner;

        public async Task<AuditLog> WriteAsync(AuditLogRequest request,
            CancellationToken cancellationToken = default)
        {
            await _inner.WriteAsync(request, cancellationToken);
            throw new InjectedFailureException();
        }

        public Task<IReadOnlyList<AuditLog>> GetLatestAsync(int take = 200,
            CancellationToken cancellationToken = default) =>
            _inner.GetLatestAsync(take, cancellationToken);

        public Task<IReadOnlyList<AuditLog>> GetForCaseAsync(Guid id, int take = 200,
            CancellationToken cancellationToken = default) =>
            _inner.GetForCaseAsync(id, take, cancellationToken);

        public Task<IReadOnlyList<AuditLog>> SearchAsync(string? searchTerm = null,
            AuditAction? action = null, bool? isSuccessful = null, int take = 500,
            CancellationToken cancellationToken = default) =>
            _inner.SearchAsync(searchTerm, action, isSuccessful, take, cancellationToken);
    }
}
