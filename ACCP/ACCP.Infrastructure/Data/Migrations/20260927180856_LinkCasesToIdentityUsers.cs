using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ACCP.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class LinkCasesToIdentityUsers : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CyberCases_UserProfiles_ReporterId",
                table: "CyberCases");

            migrationBuilder.DropIndex(
                name: "IX_CyberCases_ReporterId",
                table: "CyberCases");

            migrationBuilder.AddColumn<Guid>(
                name: "PlatformUserId",
                table: "CyberCases",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_CyberCases_PlatformUserId",
                table: "CyberCases",
                column: "PlatformUserId");

            migrationBuilder.AddForeignKey(
                name: "FK_CyberCases_UserProfiles_PlatformUserId",
                table: "CyberCases",
                column: "PlatformUserId",
                principalTable: "UserProfiles",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CyberCases_UserProfiles_PlatformUserId",
                table: "CyberCases");

            migrationBuilder.DropIndex(
                name: "IX_CyberCases_PlatformUserId",
                table: "CyberCases");

            migrationBuilder.DropColumn(
                name: "PlatformUserId",
                table: "CyberCases");

            migrationBuilder.CreateIndex(
                name: "IX_CyberCases_ReporterId",
                table: "CyberCases",
                column: "ReporterId");

            migrationBuilder.AddForeignKey(
                name: "FK_CyberCases_UserProfiles_ReporterId",
                table: "CyberCases",
                column: "ReporterId",
                principalTable: "UserProfiles",
                principalColumn: "Id");
        }
    }
}
