using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Alastor.Server.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class FirewallAndImages : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Image",
                table: "Vulnerabilities",
                type: "TEXT",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ImageVulnCritical",
                table: "Hosts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ImageVulnHigh",
                table: "Hosts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ImagesScanned",
                table: "Hosts",
                type: "INTEGER",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Image",
                table: "Vulnerabilities");

            migrationBuilder.DropColumn(
                name: "ImageVulnCritical",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "ImageVulnHigh",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "ImagesScanned",
                table: "Hosts");
        }
    }
}
