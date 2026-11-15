using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ACCP.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCaseStatusChangeReason : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Reason",
                table: "CaseStatusHistories",
                type: "nvarchar(1000)",
                maxLength: 1000,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Reason",
                table: "CaseStatusHistories");
        }
    }
}
