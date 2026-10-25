using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Alastor.Server.Data.Migrations.Postgres
{
    /// <inheritdoc />
    public partial class Integrity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "IntegrityChanges",
                table: "PostureSnapshots",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RootkitWarnings",
                table: "PostureSnapshots",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "IntegrityChanges",
                table: "Hosts",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "IntegrityCheckedAt",
                table: "Hosts",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "IntegrityCritical",
                table: "Hosts",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "RootkitCheckedAt",
                table: "Hosts",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RootkitSeverity",
                table: "Hosts",
                type: "integer",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RootkitWarnings",
                table: "Hosts",
                type: "integer",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IntegrityChanges",
                table: "PostureSnapshots");

            migrationBuilder.DropColumn(
                name: "RootkitWarnings",
                table: "PostureSnapshots");

            migrationBuilder.DropColumn(
                name: "IntegrityChanges",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "IntegrityCheckedAt",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "IntegrityCritical",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "RootkitCheckedAt",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "RootkitSeverity",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "RootkitWarnings",
                table: "Hosts");
        }
    }
}
