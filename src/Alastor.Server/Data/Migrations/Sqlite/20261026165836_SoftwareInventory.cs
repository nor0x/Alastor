using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Alastor.Server.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class SoftwareInventory : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "PackagesManual",
                table: "Hosts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "PackagesTotal",
                table: "Hosts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "SoftwareCollectedAt",
                table: "Hosts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ResultDetail",
                table: "Commands",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "OsvPackages",
                columns: table => new
                {
                    Ecosystem = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Package = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Version = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    VulnIds = table.Column<string>(type: "TEXT", nullable: false),
                    CheckedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OsvPackages", x => new { x.Ecosystem, x.Package, x.Version });
                });

            migrationBuilder.CreateTable(
                name: "OsvVulnerabilities",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    Summary = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    Severity = table.Column<int>(type: "INTEGER", maxLength: 32, nullable: true),
                    Cvss = table.Column<double>(type: "REAL", nullable: true),
                    Aliases = table.Column<string>(type: "TEXT", nullable: false),
                    Fixed = table.Column<string>(type: "TEXT", nullable: false),
                    Modified = table.Column<DateTime>(type: "TEXT", nullable: true),
                    FetchedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OsvVulnerabilities", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Packages",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    HostId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Version = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Arch = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    Source = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Manual = table.Column<bool>(type: "INTEGER", nullable: false),
                    Protected = table.Column<bool>(type: "INTEGER", nullable: false),
                    SizeKb = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Packages", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Packages_Hosts_HostId",
                        column: x => x.HostId,
                        principalTable: "Hosts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_OsvPackages_CheckedAt",
                table: "OsvPackages",
                column: "CheckedAt");

            migrationBuilder.CreateIndex(
                name: "IX_Packages_HostId",
                table: "Packages",
                column: "HostId");

            migrationBuilder.CreateIndex(
                name: "IX_Packages_Name",
                table: "Packages",
                column: "Name");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "OsvPackages");

            migrationBuilder.DropTable(
                name: "OsvVulnerabilities");

            migrationBuilder.DropTable(
                name: "Packages");

            migrationBuilder.DropColumn(
                name: "PackagesManual",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "PackagesTotal",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "SoftwareCollectedAt",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "ResultDetail",
                table: "Commands");
        }
    }
}
