using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Server.Data.Migrations.Postgres
{
    /// <inheritdoc />
    public partial class Network : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "NetworkCheckedAt",
                table: "Hosts",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ObservedAddress",
                table: "Hosts",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SshExposure",
                table: "Hosts",
                type: "character varying(24)",
                maxLength: 24,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "SshExposureAccepted",
                table: "Hosts",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "SshPasswordAuth",
                table: "Hosts",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TailscaleIp",
                table: "Hosts",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TailscaleState",
                table: "Hosts",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "NetworkCheckedAt",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "ObservedAddress",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "SshExposure",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "SshExposureAccepted",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "SshPasswordAuth",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "TailscaleIp",
                table: "Hosts");

            migrationBuilder.DropColumn(
                name: "TailscaleState",
                table: "Hosts");
        }
    }
}
