using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Sentinel.Server.Data.Migrations.Postgres
{
    /// <inheritdoc />
    public partial class Hardening : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "HardeningAuditedAt",
                table: "Hosts",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "HardeningIndex",
                table: "Hosts",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "HardeningSuggestions",
                table: "Hosts",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "HardeningWarnings",
                table: "Hosts",
                type: "integer",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "HardeningItems",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    HostId = table.Column<Guid>(type: "uuid", nullable: false),
                    TestId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Text = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Details = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    Solution = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    Accepted = table.Column<bool>(type: "boolean", nullable: false),
                    FirstSeenAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HardeningItems", x => x.Id);
                    table.ForeignKey(
                        name: "FK_HardeningItems_Hosts_HostId",
                        column: x => x.HostId,
                        principalTable: "Hosts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_HardeningItems_HostId",
                table: "HardeningItems",
                column: "HostId");

            migrationBuilder.CreateIndex(
                name: "IX_HardeningItems_TestId",
                table: "HardeningItems",
                column: "TestId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "HardeningItems");

            migrationBuilder.DropColumn(
                name: "HardeningAuditedAt",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "HardeningIndex",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "HardeningSuggestions",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "HardeningWarnings",
                table: "Hosts");
        }
    }
}
