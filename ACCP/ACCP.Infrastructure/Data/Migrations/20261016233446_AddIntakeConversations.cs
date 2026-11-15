using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ACCP.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddIntakeConversations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "IntakeConversations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ReporterId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Title = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    Status = table.Column<int>(type: "int", nullable: false),
                    CyberCaseId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    FormalReportConsentAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IntakeConversations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_IntakeConversations_AspNetUsers_ReporterId",
                        column: x => x.ReporterId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_IntakeConversations_CyberCases_CyberCaseId",
                        column: x => x.CyberCaseId,
                        principalTable: "CyberCases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "IntakeConversationMessages",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ConversationId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SequenceNumber = table.Column<long>(type: "bigint", nullable: false),
                    Role = table.Column<int>(type: "int", nullable: false),
                    AuthorUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Content = table.Column<string>(type: "nvarchar(max)", maxLength: 6000, nullable: false),
                    OperationId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IntakeConversationMessages", x => x.Id);
                    table.CheckConstraint("CK_IntakeMessage_Author", "([Role] IN (0, 2) AND [AuthorUserId] IS NOT NULL) OR ([Role] IN (1, 3) AND [AuthorUserId] IS NULL)");
                    table.CheckConstraint("CK_IntakeMessage_Operation", "[OperationId] <> '00000000-0000-0000-0000-000000000000'");
                    table.CheckConstraint("CK_IntakeMessage_Role", "[Role] IN (0, 1, 2, 3)");
                    table.CheckConstraint("CK_IntakeMessage_Sequence", "[SequenceNumber] > 0");
                    table.ForeignKey(
                        name: "FK_IntakeConversationMessages_AspNetUsers_AuthorUserId",
                        column: x => x.AuthorUserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_IntakeConversationMessages_IntakeConversations_ConversationId",
                        column: x => x.ConversationId,
                        principalTable: "IntakeConversations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_IntakeConversationMessages_AuthorUserId",
                table: "IntakeConversationMessages",
                column: "AuthorUserId");

            migrationBuilder.CreateIndex(
                name: "IX_IntakeConversationMessages_ConversationId_OperationId_Role",
                table: "IntakeConversationMessages",
                columns: new[] { "ConversationId", "OperationId", "Role" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_IntakeConversationMessages_ConversationId_SequenceNumber",
                table: "IntakeConversationMessages",
                columns: new[] { "ConversationId", "SequenceNumber" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_IntakeConversations_CyberCaseId",
                table: "IntakeConversations",
                column: "CyberCaseId",
                unique: true,
                filter: "[CyberCaseId] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_IntakeConversations_ReporterId_UpdatedAtUtc",
                table: "IntakeConversations",
                columns: new[] { "ReporterId", "UpdatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_IntakeConversations_Status_UpdatedAtUtc",
                table: "IntakeConversations",
                columns: new[] { "Status", "UpdatedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "IntakeConversationMessages");

            migrationBuilder.DropTable(
                name: "IntakeConversations");
        }
    }
}
