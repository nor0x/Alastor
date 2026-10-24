using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Server.Data.Migrations.Sqlite
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
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "VulnFixable",
                table: "Hosts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "VulnHigh",
                table: "Hosts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "VulnScannedAt",
                table: "Hosts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "VulnTotal",
                table: "Hosts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "Vulnerabilities",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    HostId = table.Column<Guid>(type: "TEXT", nullable: false),
                    VulnId = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    Package = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Installed = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Fixed = table.Column<string>(type: "TEXT", maxLength: 400, nullable: true),
                    Severity = table.Column<int>(type: "INTEGER", maxLength: 32, nullable: false),
                    Cvss = table.Column<double>(type: "REAL", nullable: true),
                    Fix = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Title = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    PkgType = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Path = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    Accepted = table.Column<bool>(type: "INTEGER", nullable: false),
                    FirstSeenAt = table.Column<DateTime>(type: "TEXT", nullable: false)
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
