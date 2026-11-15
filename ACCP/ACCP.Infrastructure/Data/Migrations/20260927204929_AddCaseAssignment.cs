using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ACCP.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCaseAssignment : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "AssignedAtUtc",
                table: "CyberCases",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AssignedOfficerEmail",
                table: "CyberCases",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "AssignedOfficerId",
                table: "CyberCases",
                type: "uniqueidentifier",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AssignedAtUtc",
                table: "CyberCases");

            migrationBuilder.DropColumn(
                name: "AssignedOfficerEmail",
                table: "CyberCases");

            migrationBuilder.DropColumn(
                name: "AssignedOfficerId",
                table: "CyberCases");
        }
    }
}
