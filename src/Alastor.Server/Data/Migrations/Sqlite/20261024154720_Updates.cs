using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Alastor.Server.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class Updates : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "PendingUpdates",
                table: "Hosts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "RebootRequired",
                table: "Hosts",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "SecurityUpdates",
                table: "Hosts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "UpdatesCheckedAt",
                table: "Hosts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "HostReports",
                columns: table => new
                {
                    HostId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Kind = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    JobId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Success = table.Column<bool>(type: "INTEGER", nullable: false),
                    Error = table.Column<string>(type: "TEXT", nullable: true),
                    StartedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    FinishedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ReceivedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Json = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HostReports", x => new { x.HostId, x.Kind });
                    table.ForeignKey(
                        name: "FK_HostReports_Hosts_HostId",
                        column: x => x.HostId,
                        principalTable: "Hosts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "HostReports");

            migrationBuilder.DropColumn(
                name: "PendingUpdates",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "RebootRequired",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "SecurityUpdates",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "UpdatesCheckedAt",
                table: "Hosts");
        }
    }
}
