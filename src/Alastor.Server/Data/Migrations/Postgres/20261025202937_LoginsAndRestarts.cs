using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Alastor.Server.Data.Migrations.Postgres
{
    /// <inheritdoc />
    public partial class LoginsAndRestarts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ServicesNeedingRestart",
                table: "Hosts",
                type: "text",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "LoginSources",
                columns: table => new
                {
                    HostId = table.Column<Guid>(type: "uuid", nullable: false),
                    User = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Address = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    FirstSeenAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeenAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastMethod = table.Column<string>(type: "character varying(48)", maxLength: 48, nullable: false),
                    Logins = table.Column<int>(type: "integer", nullable: false),
                    Alerted = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LoginSources", x => new { x.HostId, x.User, x.Address });
                    table.ForeignKey(
                        name: "FK_LoginSources_Hosts_HostId",
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
                name: "LoginSources");

            migrationBuilder.DropColumn(
                name: "ServicesNeedingRestart",
                table: "Hosts");
        }
    }
}
