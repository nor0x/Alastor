using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Server.Data.Migrations.Postgres
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
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "BaselineRevision",
                table: "Hosts",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "BaselineScore",
                table: "Hosts",
                type: "integer",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "BaselineChecks",
                columns: table => new
                {
                    HostId = table.Column<Guid>(type: "uuid", nullable: false),
                    CheckId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Actual = table.Column<string>(type: "text", nullable: false),
                    Detail = table.Column<string>(type: "text", nullable: true),
                    Commands = table.Column<string>(type: "text", nullable: false),
                    Enforced = table.Column<bool>(type: "boolean", nullable: false),
                    Accepted = table.Column<bool>(type: "boolean", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FailingSince = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
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
