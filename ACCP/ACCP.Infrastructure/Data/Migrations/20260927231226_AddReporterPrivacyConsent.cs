using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ACCP.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddReporterPrivacyConsent : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "DisclosedReporterEmail",
                table: "CyberCases",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DisclosedReporterName",
                table: "CyberCases",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsReporterIdentityDisclosed",
                table: "CyberCases",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTime>(
                name: "ReporterIdentityDisclosedAtUtc",
                table: "CyberCases",
                type: "datetime2",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DisclosedReporterEmail",
                table: "CyberCases");

            migrationBuilder.DropColumn(
                name: "DisclosedReporterName",
                table: "CyberCases");

            migrationBuilder.DropColumn(
                name: "IsReporterIdentityDisclosed",
                table: "CyberCases");

            migrationBuilder.DropColumn(
                name: "ReporterIdentityDisclosedAtUtc",
                table: "CyberCases");
        }
    }
}
