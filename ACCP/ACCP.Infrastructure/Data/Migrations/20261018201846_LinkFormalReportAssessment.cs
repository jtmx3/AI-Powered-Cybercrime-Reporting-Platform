using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ACCP.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class LinkFormalReportAssessment : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "FormalReportAssessmentId",
                table: "IntakeConversations",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddUniqueConstraint(
                name: "AK_IntakeRiskAssessments_ConversationId_Id",
                table: "IntakeRiskAssessments",
                columns: new[] { "ConversationId", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_IntakeConversations_Id_FormalReportAssessmentId",
                table: "IntakeConversations",
                columns: new[] { "Id", "FormalReportAssessmentId" });

            migrationBuilder.AddForeignKey(
                name: "FK_IntakeConversations_IntakeRiskAssessments_Id_FormalReportAssessmentId",
                table: "IntakeConversations",
                columns: new[] { "Id", "FormalReportAssessmentId" },
                principalTable: "IntakeRiskAssessments",
                principalColumns: new[] { "ConversationId", "Id" },
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_IntakeConversations_IntakeRiskAssessments_Id_FormalReportAssessmentId",
                table: "IntakeConversations");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_IntakeRiskAssessments_ConversationId_Id",
                table: "IntakeRiskAssessments");

            migrationBuilder.DropIndex(
                name: "IX_IntakeConversations_Id_FormalReportAssessmentId",
                table: "IntakeConversations");

            migrationBuilder.DropColumn(
                name: "FormalReportAssessmentId",
                table: "IntakeConversations");
        }
    }
}
