using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Alastor.Server.Data.Migrations.Postgres
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
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "PackagesTotal",
                table: "Hosts",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "SoftwareCollectedAt",
                table: "Hosts",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ResultDetail",
                table: "Commands",
                type: "text",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "OsvPackages",
                columns: table => new
                {
                    Ecosystem = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Package = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Version = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    VulnIds = table.Column<string>(type: "text", nullable: false),
                    CheckedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OsvPackages", x => new { x.Ecosystem, x.Package, x.Version });
                });

            migrationBuilder.CreateTable(
                name: "OsvVulnerabilities",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    Summary = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    Severity = table.Column<int>(type: "integer", maxLength: 32, nullable: true),
                    Cvss = table.Column<double>(type: "double precision", nullable: true),
                    Aliases = table.Column<string>(type: "text", nullable: false),
                    Fixed = table.Column<string>(type: "text", nullable: false),
                    Modified = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    FetchedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OsvVulnerabilities", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Packages",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    HostId = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Version = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Arch = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    Source = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    Manual = table.Column<bool>(type: "boolean", nullable: false),
                    Protected = table.Column<bool>(type: "boolean", nullable: false),
                    SizeKb = table.Column<long>(type: "bigint", nullable: true)
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
