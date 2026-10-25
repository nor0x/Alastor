using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Alastor.Server.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class Posture : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PostureSnapshots",
                columns: table => new
                {
                    HostId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Day = table.Column<DateOnly>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Online = table.Column<bool>(type: "INTEGER", nullable: false),
                    BaselineScore = table.Column<int>(type: "INTEGER", nullable: true),
                    HardeningIndex = table.Column<int>(type: "INTEGER", nullable: true),
                    VulnCritical = table.Column<int>(type: "INTEGER", nullable: true),
                    VulnHigh = table.Column<int>(type: "INTEGER", nullable: true),
                    VulnKev = table.Column<int>(type: "INTEGER", nullable: true),
                    SecurityUpdates = table.Column<int>(type: "INTEGER", nullable: true),
                    RebootRequired = table.Column<bool>(type: "INTEGER", nullable: false),
                    PublicSsh = table.Column<bool>(type: "INTEGER", nullable: true),
                    MalwareFindings = table.Column<int>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PostureSnapshots", x => new { x.HostId, x.Day });
                    table.ForeignKey(
                        name: "FK_PostureSnapshots_Hosts_HostId",
                        column: x => x.HostId,
                        principalTable: "Hosts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PostureSnapshots_Day",
                table: "PostureSnapshots",
                column: "Day");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PostureSnapshots");
        }
    }
}
