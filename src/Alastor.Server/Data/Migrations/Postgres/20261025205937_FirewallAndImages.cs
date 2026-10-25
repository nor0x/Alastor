using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Alastor.Server.Data.Migrations.Postgres
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
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ImageVulnCritical",
                table: "Hosts",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ImageVulnHigh",
                table: "Hosts",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ImagesScanned",
                table: "Hosts",
                type: "integer",
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
