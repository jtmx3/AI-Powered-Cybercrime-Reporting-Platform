using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ACCP.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCaseMessages : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CaseNote_CyberCases_CyberCaseId",
                table: "CaseNote");

            migrationBuilder.DropPrimaryKey(
                name: "PK_CaseNote",
                table: "CaseNote");

            migrationBuilder.RenameTable(
                name: "CaseNote",
                newName: "CaseNotes");

            migrationBuilder.RenameIndex(
                name: "IX_CaseNote_CyberCaseId",
                table: "CaseNotes",
                newName: "IX_CaseNotes_CyberCaseId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_CaseNotes",
                table: "CaseNotes",
                column: "Id");

            migrationBuilder.CreateTable(
                name: "CaseMessages",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CyberCaseId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Content = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: false),
                    SenderId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SenderEmail = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    SenderType = table.Column<int>(type: "int", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaseMessages", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CaseMessages_CyberCases_CyberCaseId",
                        column: x => x.CyberCaseId,
                        principalTable: "CyberCases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CaseMessages_CyberCaseId",
                table: "CaseMessages",
                column: "CyberCaseId");

            migrationBuilder.AddForeignKey(
                name: "FK_CaseNotes_CyberCases_CyberCaseId",
                table: "CaseNotes",
                column: "CyberCaseId",
                principalTable: "CyberCases",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CaseNotes_CyberCases_CyberCaseId",
                table: "CaseNotes");

            migrationBuilder.DropTable(
                name: "CaseMessages");

            migrationBuilder.DropPrimaryKey(
                name: "PK_CaseNotes",
                table: "CaseNotes");

            migrationBuilder.RenameTable(
                name: "CaseNotes",
                newName: "CaseNote");

            migrationBuilder.RenameIndex(
                name: "IX_CaseNotes_CyberCaseId",
                table: "CaseNote",
                newName: "IX_CaseNote_CyberCaseId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_CaseNote",
                table: "CaseNote",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_CaseNote_CyberCases_CyberCaseId",
                table: "CaseNote",
                column: "CyberCaseId",
                principalTable: "CyberCases",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
