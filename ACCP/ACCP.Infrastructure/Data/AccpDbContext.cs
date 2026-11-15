using ACCP.Domain.Entities;
using ACCP.Domain.Enums;
using ACCP.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ACCP.Infrastructure.Data;

public class AccpDbContext
    : IdentityDbContext<
        ApplicationUser,
        IdentityRole<Guid>,
        Guid>
{
    public AccpDbContext(
        DbContextOptions<AccpDbContext> options)
        : base(options)
    {
    }

    public DbSet<PlatformUser> UserProfiles =>
        Set<PlatformUser>();

    public DbSet<CyberCase> CyberCases =>
        Set<CyberCase>();

    public DbSet<AuditLog> AuditLogs =>
        Set<AuditLog>();

    public DbSet<Evidence> EvidenceItems =>
        Set<Evidence>();

    public DbSet<EvidenceRevision> EvidenceRevisions =>
        Set<EvidenceRevision>();

    public DbSet<CaseStatusHistory> CaseStatusHistories =>
        Set<CaseStatusHistory>();

    public DbSet<CaseNote> CaseNotes =>
        Set<CaseNote>();

    public DbSet<CaseMessage> CaseMessages =>
        Set<CaseMessage>();

    public DbSet<UserNotification> UserNotifications =>
        Set<UserNotification>();

    public DbSet<CaseStaffRequest> CaseStaffRequests =>
        Set<CaseStaffRequest>();

    public DbSet<CaseCollaborator> CaseCollaborators =>
        Set<CaseCollaborator>();

    public DbSet<IntakeConversation> IntakeConversations =>
        Set<IntakeConversation>();

    public DbSet<IntakeConversationMessage> IntakeConversationMessages =>
        Set<IntakeConversationMessage>();

    public DbSet<IntakeRiskAssessment> IntakeRiskAssessments =>
        Set<IntakeRiskAssessment>();

    protected override void OnModelCreating(
        ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<IntakeConversation>(entity =>
        {
            entity.ToTable("IntakeConversations");

            entity.Property(item => item.Title)
                .HasMaxLength(200)
                .IsRequired();

            entity.Property(item => item.RowVersion)
                .IsRowVersion();

            entity.HasIndex(item => new
            {
                item.ReporterId,
                item.UpdatedAtUtc
            });

            entity.HasIndex(item => new
            {
                item.Status,
                item.UpdatedAtUtc
            });

            entity.HasOne<ApplicationUser>()
                .WithMany()
                .HasForeignKey(item => item.ReporterId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(item => item.CyberCase)
                .WithOne()
                .HasForeignKey<IntakeConversation>(
                    item => item.CyberCaseId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasIndex(item => item.CyberCaseId)
                .IsUnique()
                .HasFilter("[CyberCaseId] IS NOT NULL");
        });

        builder.Entity<IntakeConversationMessage>(entity =>
        {
            entity.ToTable("IntakeConversationMessages", table =>
            {
                table.HasCheckConstraint(
                    "CK_IntakeMessage_Sequence",
                    "[SequenceNumber] > 0");

                table.HasCheckConstraint(
                    "CK_IntakeMessage_Role",
                    "[Role] IN (0, 1, 2, 3)");

                table.HasCheckConstraint(
                    "CK_IntakeMessage_Operation",
                    "[OperationId] <> '00000000-0000-0000-0000-000000000000'");

                table.HasCheckConstraint(
                    "CK_IntakeMessage_Author",
                    "([Role] IN (0, 2) AND [AuthorUserId] IS NOT NULL) OR ([Role] IN (1, 3) AND [AuthorUserId] IS NULL)");
            });

            entity.Property(item => item.Content)
                .HasMaxLength(6000)
                .IsRequired();

            entity.HasOne(item => item.Conversation)
                .WithMany()
                .HasForeignKey(item => item.ConversationId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne<ApplicationUser>()
                .WithMany()
                .HasForeignKey(item => item.AuthorUserId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasIndex(item => new
            {
                item.ConversationId,
                item.SequenceNumber
            }).IsUnique();

            entity.HasIndex(item => new
            {
                item.ConversationId,
                item.OperationId,
                item.Role
            }).IsUnique();
        });

        // يمنع ربط التقييم برسالة من محادثة أخرى.
        builder.Entity<IntakeConversationMessage>()
            .HasAlternateKey(item => new
            {
                item.ConversationId,
                item.Id
            });

        builder.Entity<IntakeRiskAssessment>(entity =>
        {
            entity.ToTable("IntakeRiskAssessments", table =>
            {
                table.HasCheckConstraint(
                    "CK_IntakeRiskAssessment_Risk",
                    "[RiskPercentage] >= 0 AND [RiskPercentage] <= 100");

                table.HasCheckConstraint(
                    "CK_IntakeRiskAssessment_Sequence",
                    "[BasedOnSequenceNumber] > 0");

                table.HasCheckConstraint(
                    "CK_IntakeRiskAssessment_IncidentType",
                    "[IncidentType] IN ('Blackmail', 'Fraud', 'AccountHacking', 'IdentityTheft', 'Threat', 'Other')");
            });

            entity.Property(item => item.RiskPercentage)
                .HasPrecision(29, 26);

            entity.Property(item => item.Title)
                .HasMaxLength(200)
                .IsRequired();

            entity.Property(item => item.Summary)
                .HasMaxLength(4000)
                .IsRequired();

            entity.Property(item => item.IncidentType)
                .HasMaxLength(50)
                .IsRequired();

            entity.Property(item => item.RiskExplanation)
                .HasMaxLength(2000)
                .IsRequired();

            entity.HasOne<IntakeConversation>()
                .WithMany()
                .HasForeignKey(item => item.ConversationId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne<IntakeConversationMessage>()
                .WithMany()
                .HasForeignKey(item => new
                {
                    item.ConversationId,
                    item.AssistantMessageId
                })
                .HasPrincipalKey(item => new
                {
                    item.ConversationId,
                    item.Id
                })
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasIndex(item => item.AssistantMessageId)
                .IsUnique();

            entity.HasIndex(item => new
            {
                item.ConversationId,
                item.BasedOnSequenceNumber
            });
        });

        // يتيح التحقق من انتماء التقييم المعتمد للمحادثة نفسها.
        builder.Entity<IntakeRiskAssessment>()
            .HasAlternateKey(item => new
            {
                item.ConversationId,
                item.Id
            });

        // العلاقة اختيارية قبل تقديم البلاغ.
        // لا يمكن اعتماد تقييم تابع لمحادثة أخرى.
        builder.Entity<IntakeConversation>()
            .HasOne<IntakeRiskAssessment>()
            .WithMany()
            .HasForeignKey(item => new
            {
                item.Id,
                item.FormalReportAssessmentId
            })
            .HasPrincipalKey(item => new
            {
                item.ConversationId,
                item.Id
            })
            .IsRequired(false)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<CyberCase>()
            .Property(item => item.Path)
            .HasDefaultValue(CasePath.FormalReport)
            .HasSentinel(CasePath.FormalReport);

        builder.Entity<CyberCase>()
            .HasIndex(item => item.CaseNumber)
            .IsUnique();

        builder.Entity<CyberCase>()
            .HasIndex(item => new
            {
                item.ReporterId,
                item.CreatedAtUtc
            });

        builder.Entity<CyberCase>()
            .HasIndex(item => new
            {
                item.AssignedOfficerId,
                item.Status
            });

        builder.Entity<CaseMessage>()
            .HasIndex(item => new
            {
                item.CyberCaseId,
                item.CreatedAtUtc
            });

        builder.Entity<CaseNote>()
            .HasIndex(item => new
            {
                item.CyberCaseId,
                item.CreatedAtUtc
            });

        builder.Entity<AuditLog>()
            .HasIndex(item => new
            {
                item.CyberCaseId,
                item.CreatedAtUtc
            });

        builder.Entity<UserNotification>()
            .HasIndex(item => new
            {
                item.RecipientUserId,
                item.CreatedAtUtc
            });

        builder.Entity<UserNotification>()
            .HasIndex(item => new
            {
                item.RecipientUserId,
                item.IsRead
            });

        builder.Entity<EvidenceRevision>()
            .HasOne(revision => revision.Evidence)
            .WithMany(evidence => evidence.Revisions)
            .HasForeignKey(revision => revision.EvidenceId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<EvidenceRevision>()
            .HasIndex(revision => new
            {
                revision.EvidenceId,
                revision.VersionNumber
            })
            .IsUnique();

        builder.Entity<CaseStaffRequest>()
            .HasOne(request => request.CyberCase)
            .WithMany(cyberCase => cyberCase.StaffRequests)
            .HasForeignKey(request => request.CyberCaseId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.Entity<CaseStaffRequest>()
            .HasIndex(request => new
            {
                request.Status,
                request.CreatedAtUtc
            });

        builder.Entity<CaseStaffRequest>()
            .HasIndex(request => new
            {
                request.RequestedByOfficerId,
                request.Status
            });

        builder.Entity<CaseCollaborator>()
            .HasOne(collaborator => collaborator.CyberCase)
            .WithMany(cyberCase => cyberCase.Collaborators)
            .HasForeignKey(collaborator => collaborator.CyberCaseId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.Entity<CaseCollaborator>()
            .HasIndex(collaborator => new
            {
                collaborator.CyberCaseId,
                collaborator.OfficerId
            })
            .IsUnique();

        builder.Entity<CaseCollaborator>()
            .HasIndex(collaborator => new
            {
                collaborator.OfficerId,
                collaborator.IsActive
            });

        builder.Entity<CaseCollaborator>()
            .HasIndex(collaborator => collaborator.SourceRequestId)
            .IsUnique();
    }
}