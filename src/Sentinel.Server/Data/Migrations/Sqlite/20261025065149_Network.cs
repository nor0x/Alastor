using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Server.Data.Migrations.Sqlite
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
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ObservedAddress",
                table: "Hosts",
                type: "TEXT",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SshExposure",
                table: "Hosts",
                type: "TEXT",
                maxLength: 24,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "SshExposureAccepted",
                table: "Hosts",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "SshPasswordAuth",
                table: "Hosts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TailscaleIp",
                table: "Hosts",
                type: "TEXT",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TailscaleState",
                table: "Hosts",
                type: "TEXT",
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
