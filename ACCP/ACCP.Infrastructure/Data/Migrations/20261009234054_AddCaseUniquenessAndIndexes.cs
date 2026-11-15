using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ACCP.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCaseUniquenessAndIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_CaseNotes_CyberCaseId",
                table: "CaseNotes");

            migrationBuilder.DropIndex(
                name: "IX_CaseMessages_CyberCaseId",
                table: "CaseMessages");

            migrationBuilder.CreateIndex(
                name: "IX_UserNotifications_RecipientUserId_CreatedAtUtc",
                table: "UserNotifications",
                columns: new[] { "RecipientUserId", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_UserNotifications_RecipientUserId_IsRead",
                table: "UserNotifications",
                columns: new[] { "RecipientUserId", "IsRead" });

            migrationBuilder.CreateIndex(
                name: "IX_CyberCases_AssignedOfficerId_Status",
                table: "CyberCases",
                columns: new[] { "AssignedOfficerId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_CyberCases_CaseNumber",
                table: "CyberCases",
                column: "CaseNumber",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CyberCases_ReporterId_CreatedAtUtc",
                table: "CyberCases",
                columns: new[] { "ReporterId", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_CaseNotes_CyberCaseId_CreatedAtUtc",
                table: "CaseNotes",
                columns: new[] { "CyberCaseId", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_CaseMessages_CyberCaseId_CreatedAtUtc",
                table: "CaseMessages",
                columns: new[] { "CyberCaseId", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_CyberCaseId_CreatedAtUtc",
                table: "AuditLogs",
                columns: new[] { "CyberCaseId", "CreatedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_UserNotifications_RecipientUserId_CreatedAtUtc",
                table: "UserNotifications");

            migrationBuilder.DropIndex(
                name: "IX_UserNotifications_RecipientUserId_IsRead",
                table: "UserNotifications");

            migrationBuilder.DropIndex(
                name: "IX_CyberCases_AssignedOfficerId_Status",
                table: "CyberCases");

            migrationBuilder.DropIndex(
                name: "IX_CyberCases_CaseNumber",
                table: "CyberCases");

            migrationBuilder.DropIndex(
                name: "IX_CyberCases_ReporterId_CreatedAtUtc",
                table: "CyberCases");

            migrationBuilder.DropIndex(
                name: "IX_CaseNotes_CyberCaseId_CreatedAtUtc",
                table: "CaseNotes");

            migrationBuilder.DropIndex(
                name: "IX_CaseMessages_CyberCaseId_CreatedAtUtc",
                table: "CaseMessages");

            migrationBuilder.DropIndex(
                name: "IX_AuditLogs_CyberCaseId_CreatedAtUtc",
                table: "AuditLogs");

            migrationBuilder.CreateIndex(
                name: "IX_CaseNotes_CyberCaseId",
                table: "CaseNotes",
                column: "CyberCaseId");

            migrationBuilder.CreateIndex(
                name: "IX_CaseMessages_CyberCaseId",
                table: "CaseMessages",
                column: "CyberCaseId");
        }
    }
}
