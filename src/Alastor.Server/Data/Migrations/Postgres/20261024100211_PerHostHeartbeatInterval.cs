using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Alastor.Server.Data.Migrations.Postgres
{
    /// <inheritdoc />
    public partial class PerHostHeartbeatInterval : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "HeartbeatIntervalSeconds",
                table: "Hosts",
                type: "integer",
                nullable: false,
                defaultValue: 60); // existing hosts: the previous fixed heartbeat
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "HeartbeatIntervalSeconds",
                table: "Hosts");
        }
    }
}
