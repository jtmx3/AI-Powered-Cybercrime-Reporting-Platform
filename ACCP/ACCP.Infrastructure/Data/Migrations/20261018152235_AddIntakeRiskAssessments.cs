using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ACCP.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddIntakeRiskAssessments : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddUniqueConstraint(
                name: "AK_IntakeConversationMessages_ConversationId_Id",
                table: "IntakeConversationMessages",
                columns: new[] { "ConversationId", "Id" });

            migrationBuilder.CreateTable(
                name: "IntakeRiskAssessments",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ConversationId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AssistantMessageId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    BasedOnSequenceNumber = table.Column<long>(type: "bigint", nullable: false),
                    Title = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    Summary = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: false),
                    IncidentType = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    RiskPercentage = table.Column<decimal>(type: "decimal(29,26)", precision: 29, scale: 26, nullable: false),
                    RiskExplanation = table.Column<string>(type: "nvarchar(2000)", maxLength: 2000, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IntakeRiskAssessments", x => x.Id);
                    table.CheckConstraint("CK_IntakeRiskAssessment_IncidentType", "[IncidentType] IN ('Blackmail', 'Fraud', 'AccountHacking', 'IdentityTheft', 'Threat', 'Other')");
                    table.CheckConstraint("CK_IntakeRiskAssessment_Risk", "[RiskPercentage] >= 0 AND [RiskPercentage] <= 100");
                    table.CheckConstraint("CK_IntakeRiskAssessment_Sequence", "[BasedOnSequenceNumber] > 0");
                    table.ForeignKey(
                        name: "FK_IntakeRiskAssessments_IntakeConversationMessages_ConversationId_AssistantMessageId",
                        columns: x => new { x.ConversationId, x.AssistantMessageId },
                        principalTable: "IntakeConversationMessages",
                        principalColumns: new[] { "ConversationId", "Id" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_IntakeRiskAssessments_IntakeConversations_ConversationId",
                        column: x => x.ConversationId,
                        principalTable: "IntakeConversations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_IntakeRiskAssessments_AssistantMessageId",
                table: "IntakeRiskAssessments",
                column: "AssistantMessageId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_IntakeRiskAssessments_ConversationId_AssistantMessageId",
                table: "IntakeRiskAssessments",
                columns: new[] { "ConversationId", "AssistantMessageId" });

            migrationBuilder.CreateIndex(
                name: "IX_IntakeRiskAssessments_ConversationId_BasedOnSequenceNumber",
                table: "IntakeRiskAssessments",
                columns: new[] { "ConversationId", "BasedOnSequenceNumber" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "IntakeRiskAssessments");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_IntakeConversationMessages_ConversationId_Id",
                table: "IntakeConversationMessages");
        }
    }
}
