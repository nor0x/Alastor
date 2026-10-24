using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Server.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class Baseline : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "BaselineCheckedAt",
                table: "Hosts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "BaselineRevision",
                table: "Hosts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "BaselineScore",
                table: "Hosts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "BaselineChecks",
                columns: table => new
                {
                    HostId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CheckId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Actual = table.Column<string>(type: "TEXT", nullable: false),
                    Detail = table.Column<string>(type: "TEXT", nullable: true),
                    Commands = table.Column<string>(type: "TEXT", nullable: false),
                    Enforced = table.Column<bool>(type: "INTEGER", nullable: false),
                    Accepted = table.Column<bool>(type: "INTEGER", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    FailingSince = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BaselineChecks", x => new { x.HostId, x.CheckId });
                    table.ForeignKey(
                        name: "FK_BaselineChecks_Hosts_HostId",
                        column: x => x.HostId,
                        principalTable: "Hosts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_BaselineChecks_CheckId_Status",
                table: "BaselineChecks",
                columns: new[] { "CheckId", "Status" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "BaselineChecks");

            migrationBuilder.DropColumn(
                name: "BaselineCheckedAt",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "BaselineRevision",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "BaselineScore",
                table: "Hosts");
        }
    }
}
