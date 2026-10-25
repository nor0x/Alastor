using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Alastor.Server.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class ExposureInventory : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "PublicServices",
                table: "PostureSnapshots",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PublicServices",
                table: "Hosts",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PublicServices",
                table: "PostureSnapshots");

            migrationBuilder.DropColumn(
                name: "PublicServices",
                table: "Hosts");
        }
    }
}
