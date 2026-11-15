using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ACCP.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddEvidenceRevisionAccessAcknowledgement : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsOriginalEvidenceAccessAcknowledged",
                table: "EvidenceRevisions",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTime>(
                name: "OriginalEvidenceAccessAcknowledgedAtUtc",
                table: "EvidenceRevisions",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "OriginalEvidenceAccessAcknowledgementText",
                table: "EvidenceRevisions",
                type: "nvarchar(1000)",
                maxLength: 1000,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsOriginalEvidenceAccessAcknowledged",
                table: "EvidenceRevisions");

            migrationBuilder.DropColumn(
                name: "OriginalEvidenceAccessAcknowledgedAtUtc",
                table: "EvidenceRevisions");

            migrationBuilder.DropColumn(
                name: "OriginalEvidenceAccessAcknowledgementText",
                table: "EvidenceRevisions");
        }
    }
}
