using System.Data.Common;
using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Data;
using ACCP.Infrastructure.Identity;
using ACCP.Infrastructure.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace ACCP.Tests;

public sealed class AtomicStatusTests : IAsyncLifetime
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly Guid _owner = Guid.NewGuid();
    private readonly ChangeBeforeUpdate _interceptor = new();
    private readonly ApplicationUser _reporter = new()
    {
        Id = Guid.NewGuid(), UserName = "synthetic-reporter",
        Email = "reporter@example.test"
    };
    private AccpDbContext _db = null!;
    private CaseService _service = null!;
    private CyberCase _item = null!;

    public async Task InitializeAsync()
    {
        await _connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AccpDbContext>()
            .UseSqlite(_connection).AddInterceptors(_interceptor).Options;
        _db = new AccpDbContext(options);
        await _db.Database.EnsureCreatedAsync();
        _db.Users.Add(_reporter);
        _item = new CyberCase { CaseNumber = "SYNTHETIC", Title = "Test case",
            Description = "Synthetic incident", IncidentType = "Test",
            ReporterId = _reporter.Id, AssignedOfficerId = _owner, Status = CaseStatus.Assigned };
        _db.CyberCases.Add(_item);
        await _db.SaveChangesAsync();
        _service = new CaseService(_db, new AuditService(_db), new NotificationService(_db));
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
        await _connection.DisposeAsync();
    }

    [Fact]
    public async Task StaleTrackedStatus_UsesDatabaseStatusForHistoryAndRefreshesTracking()
    {
        await _db.CyberCases.Where(item => item.Id == _item.Id)
            .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.Status, CaseStatus.InProgress));
        Assert.Equal(CaseStatus.Assigned, _item.Status);
        Assert.True(await _service.UpdateStatusForOfficerAsync(_item.Id, CaseStatus.Resolved, _owner, "owner@example.test", "Documented resolution reason"));
        Assert.Equal(CaseStatus.InProgress, (await _db.CaseStatusHistories.SingleAsync()).OldStatus);
        Assert.Equal(CaseStatus.Resolved, _item.Status);
        var notification = await _db.UserNotifications.SingleAsync();
        Assert.Equal(_reporter.Id, notification.RecipientUserId);
        Assert.Equal(NotificationType.CaseStatusChanged, notification.Type);
        _item.Title = "Unrelated edit";
        await _db.SaveChangesAsync();
        Assert.Equal(CaseStatus.Resolved, (await _db.CyberCases.AsNoTracking().SingleAsync()).Status);
    }

    [Fact]
    public async Task StaleTrackedStatus_AlreadyCurrentRequestCreatesNoDuplicateEffects()
    {
        await _db.CyberCases.Where(item => item.Id == _item.Id)
            .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.Status, CaseStatus.InProgress));
        Assert.True(await _service.UpdateStatusForOfficerAsync(_item.Id, CaseStatus.InProgress, _owner, "owner@example.test"));
        Assert.Equal(CaseStatus.InProgress, _item.Status);
        Assert.Empty(await _db.CaseStatusHistories.ToListAsync());
        Assert.Empty(await _db.AuditLogs.ToListAsync());
        Assert.Empty(await _db.UserNotifications.ToListAsync());
    }

    [Fact]
    public async Task ChangedStatusBetweenReadAndUpdate_RejectsStaleWriteAndItsSideEffects()
    {
        _db.ChangeTracker.Clear();
        _interceptor.Arm(_item.Id, CaseStatus.InProgress);
        Assert.False(await _service.UpdateStatusForOfficerAsync(_item.Id, CaseStatus.InProgress, _owner, "owner@example.test"));
        Assert.True(_interceptor.Triggered);
        Assert.Equal(CaseStatus.InProgress, (await _db.CyberCases.AsNoTracking().SingleAsync()).Status);
        Assert.Empty(await _db.CaseStatusHistories.ToListAsync());
        Assert.Empty(await _db.AuditLogs.ToListAsync());
        Assert.Empty(await _db.UserNotifications.ToListAsync());
    }

    [Fact]
    public async Task OwnershipChangedBetweenReadAndUpdate_RejectsFormerOwnerWrite()
    {
        _db.ChangeTracker.Clear();
        var newOwner = Guid.NewGuid();
        _interceptor.ArmOwner(_item.Id, newOwner);

        Assert.False(await _service.UpdateStatusForOfficerAsync(
            _item.Id, CaseStatus.InProgress, _owner, "owner@example.test"));
        Assert.True(_interceptor.Triggered);
        var persisted = await _db.CyberCases.AsNoTracking().SingleAsync();
        Assert.Equal(newOwner, persisted.AssignedOfficerId);
        Assert.Equal(CaseStatus.Assigned, persisted.Status);
        Assert.Empty(await _db.CaseStatusHistories.ToListAsync());
        Assert.Empty(await _db.AuditLogs.ToListAsync());
        Assert.Empty(await _db.UserNotifications.ToListAsync());
    }

    // Deterministically change the row immediately before ExecuteUpdate runs.
    // This checks the conditional write; it is not a SQL Server race test.
    private sealed class ChangeBeforeUpdate : DbCommandInterceptor
    {
        private Guid? _id;
        private CaseStatus _status;
        private Guid? _newOwner;
        public bool Triggered { get; private set; }
        public void Arm(Guid id, CaseStatus status)
        {
            _id = id; _status = status; _newOwner = null;
        }
        public void ArmOwner(Guid id, Guid owner)
        {
            _id = id; _newOwner = owner;
        }

        public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            if (_id.HasValue && command.CommandText.StartsWith("UPDATE \"CyberCases\""))
            {
                var id = _id.Value;
                _id = null;
                await using var injected = command.Connection!.CreateCommand();
                injected.Transaction = command.Transaction;
                injected.CommandText = _newOwner.HasValue
                    ? "UPDATE \"CyberCases\" SET \"AssignedOfficerId\" = @value WHERE \"Id\" = @id"
                    : "UPDATE \"CyberCases\" SET \"Status\" = @value WHERE \"Id\" = @id";
                var idParameter = injected.CreateParameter();
                idParameter.ParameterName = "@id"; idParameter.Value = id;
                var valueParameter = injected.CreateParameter();
                valueParameter.ParameterName = "@value";
                valueParameter.Value = _newOwner.HasValue ? (object)_newOwner.Value : (int)_status;
                injected.Parameters.Add(idParameter); injected.Parameters.Add(valueParameter);
                Assert.Equal(1, await injected.ExecuteNonQueryAsync(cancellationToken));
                Triggered = true;
            }
            return result;
        }
    }
}
