using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ACCP.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCaseStaffRequestsAndCollaborators : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CaseCollaborators",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CyberCaseId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    OfficerId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    OfficerEmail = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    SourceRequestId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AddedByAdminId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AddedByAdminEmail = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    AddedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    RemovedByAdminId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    RemovedByAdminEmail = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    RemovalReason = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: true),
                    RemovedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaseCollaborators", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CaseCollaborators_CyberCases_CyberCaseId",
                        column: x => x.CyberCaseId,
                        principalTable: "CyberCases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CaseStaffRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CyberCaseId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequestedByOfficerId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequestedByOfficerEmail = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    RequestType = table.Column<int>(type: "int", nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: false),
                    Status = table.Column<int>(type: "int", nullable: false),
                    TargetOfficerId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    TargetOfficerEmail = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    ReviewedByAdminId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ReviewedByAdminEmail = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    DecisionNote = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ReviewedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaseStaffRequests", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CaseStaffRequests_CyberCases_CyberCaseId",
                        column: x => x.CyberCaseId,
                        principalTable: "CyberCases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CaseCollaborators_CyberCaseId_OfficerId",
                table: "CaseCollaborators",
                columns: new[] { "CyberCaseId", "OfficerId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CaseCollaborators_OfficerId_IsActive",
                table: "CaseCollaborators",
                columns: new[] { "OfficerId", "IsActive" });

            migrationBuilder.CreateIndex(
                name: "IX_CaseCollaborators_SourceRequestId",
                table: "CaseCollaborators",
                column: "SourceRequestId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CaseStaffRequests_CyberCaseId",
                table: "CaseStaffRequests",
                column: "CyberCaseId");

            migrationBuilder.CreateIndex(
                name: "IX_CaseStaffRequests_RequestedByOfficerId_Status",
                table: "CaseStaffRequests",
                columns: new[] { "RequestedByOfficerId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_CaseStaffRequests_Status_CreatedAtUtc",
                table: "CaseStaffRequests",
                columns: new[] { "Status", "CreatedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CaseCollaborators");

            migrationBuilder.DropTable(
                name: "CaseStaffRequests");
        }
    }
}
