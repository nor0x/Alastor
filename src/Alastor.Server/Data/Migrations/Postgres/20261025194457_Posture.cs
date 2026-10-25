using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Alastor.Server.Data.Migrations.Postgres
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
                    HostId = table.Column<Guid>(type: "uuid", nullable: false),
                    Day = table.Column<DateOnly>(type: "date", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Online = table.Column<bool>(type: "boolean", nullable: false),
                    BaselineScore = table.Column<int>(type: "integer", nullable: true),
                    HardeningIndex = table.Column<int>(type: "integer", nullable: true),
                    VulnCritical = table.Column<int>(type: "integer", nullable: true),
                    VulnHigh = table.Column<int>(type: "integer", nullable: true),
                    VulnKev = table.Column<int>(type: "integer", nullable: true),
                    SecurityUpdates = table.Column<int>(type: "integer", nullable: true),
                    RebootRequired = table.Column<bool>(type: "boolean", nullable: false),
                    PublicSsh = table.Column<bool>(type: "boolean", nullable: true),
                    MalwareFindings = table.Column<int>(type: "integer", nullable: true)
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
