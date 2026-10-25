using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Alastor.Server.Data.Migrations.Postgres
{
    /// <inheritdoc />
    public partial class Vulnerabilities : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "VulnCritical",
                table: "Hosts",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "VulnFixable",
                table: "Hosts",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "VulnHigh",
                table: "Hosts",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "VulnScannedAt",
                table: "Hosts",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "VulnTotal",
                table: "Hosts",
                type: "integer",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "Vulnerabilities",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    HostId = table.Column<Guid>(type: "uuid", nullable: false),
                    VulnId = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    Package = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Installed = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Fixed = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: true),
                    Severity = table.Column<int>(type: "integer", maxLength: 32, nullable: false),
                    Cvss = table.Column<double>(type: "double precision", nullable: true),
                    Fix = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Title = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    PkgType = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Path = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    Accepted = table.Column<bool>(type: "boolean", nullable: false),
                    FirstSeenAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Vulnerabilities", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Vulnerabilities_Hosts_HostId",
                        column: x => x.HostId,
                        principalTable: "Hosts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_HostId",
                table: "Vulnerabilities",
                column: "HostId");

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_VulnId",
                table: "Vulnerabilities",
                column: "VulnId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Vulnerabilities");

            migrationBuilder.DropColumn(
                name: "VulnCritical",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "VulnFixable",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "VulnHigh",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "VulnScannedAt",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "VulnTotal",
                table: "Hosts");
        }
    }
}
