using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Alastor.Server.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class Alerts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Alert",
                table: "Events",
                type: "TEXT",
                maxLength: 32,
                nullable: false,
                defaultValue: "None"); // existing events predate the alert pipeline

            migrationBuilder.CreateTable(
                name: "AlertBuckets",
                columns: table => new
                {
                    Key = table.Column<string>(type: "TEXT", maxLength: 300, nullable: false),
                    Level = table.Column<double>(type: "REAL", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastNotifiedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastSeverity = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Suppressed = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AlertBuckets", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "NotificationChannels",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Type = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    MinSeverity = table.Column<int>(type: "INTEGER", maxLength: 32, nullable: false),
                    Capabilities = table.Column<string>(type: "TEXT", nullable: false),
                    Immediate = table.Column<bool>(type: "INTEGER", nullable: false),
                    DigestSchedule = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    LastDigestAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ConfigProtected = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastAttemptAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastSuccessAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastError = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NotificationChannels", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "NotificationDeliveries",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ChannelId = table.Column<Guid>(type: "TEXT", nullable: false),
                    At = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Kind = table.Column<string>(type: "TEXT", nullable: false),
                    Title = table.Column<string>(type: "TEXT", nullable: false),
                    EventCount = table.Column<int>(type: "INTEGER", nullable: false),
                    Success = table.Column<bool>(type: "INTEGER", nullable: false),
                    Attempts = table.Column<int>(type: "INTEGER", nullable: false),
                    Error = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NotificationDeliveries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_NotificationDeliveries_NotificationChannels_ChannelId",
                        column: x => x.ChannelId,
                        principalTable: "NotificationChannels",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AlertBuckets_UpdatedAt",
                table: "AlertBuckets",
                column: "UpdatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_NotificationDeliveries_At",
                table: "NotificationDeliveries",
                column: "At");

            migrationBuilder.CreateIndex(
                name: "IX_NotificationDeliveries_ChannelId",
                table: "NotificationDeliveries",
                column: "ChannelId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AlertBuckets");

            migrationBuilder.DropTable(
                name: "NotificationDeliveries");

            migrationBuilder.DropTable(
                name: "NotificationChannels");

            migrationBuilder.DropColumn(
                name: "Alert",
                table: "Events");
        }
    }
}
