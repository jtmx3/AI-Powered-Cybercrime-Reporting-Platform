using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ACCP.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddEvidenceOfficerDisclosureConsent : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "DisclosedByReporterId",
                table: "EvidenceItems",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "DisclosedToOfficerAtUtc",
                table: "EvidenceItems",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsDisclosedToOfficer",
                table: "EvidenceItems",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DisclosedByReporterId",
                table: "EvidenceItems");

            migrationBuilder.DropColumn(
                name: "DisclosedToOfficerAtUtc",
                table: "EvidenceItems");

            migrationBuilder.DropColumn(
                name: "IsDisclosedToOfficer",
                table: "EvidenceItems");
        }
    }
}
