using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sentinel.Server.Data.Migrations.Postgres
{
    /// <inheritdoc />
    public partial class ThreatFeed : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "FeedItems",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Source = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Type = table.Column<string>(type: "character varying(8)", maxLength: 8, nullable: false),
                    SourceItemId = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Title = table.Column<string>(type: "text", nullable: false),
                    Url = table.Column<string>(type: "text", nullable: false),
                    PublishedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FetchedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Summary = table.Column<string>(type: "text", nullable: false),
                    Severity = table.Column<int>(type: "integer", maxLength: 32, nullable: true),
                    CvssScore = table.Column<double>(type: "double precision", nullable: true),
                    Exploited = table.Column<bool>(type: "boolean", nullable: false),
                    Tags = table.Column<string>(type: "text", nullable: false),
                    Products = table.Column<string>(type: "text", nullable: false),
                    CveIds = table.Column<string>(type: "text", nullable: false),
                    SearchText = table.Column<string>(type: "text", nullable: false),
                    TagIndex = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FeedItems", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "FeedSources",
                columns: table => new
                {
                    SourceId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    LastAttemptAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastSuccessAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    NextAttemptAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ConsecutiveFailures = table.Column<int>(type: "integer", nullable: false),
                    LastError = table.Column<string>(type: "text", nullable: true),
                    LastItemCount = table.Column<int>(type: "integer", nullable: false),
                    ETag = table.Column<string>(type: "text", nullable: true),
                    LastModified = table.Column<string>(type: "text", nullable: true),
                    Cursor = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FeedSources", x => x.SourceId);
                });

            migrationBuilder.CreateTable(
                name: "KevEntries",
                columns: table => new
                {
                    CveId = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    VendorProject = table.Column<string>(type: "text", nullable: false),
                    Product = table.Column<string>(type: "text", nullable: false),
                    VulnerabilityName = table.Column<string>(type: "text", nullable: false),
                    ShortDescription = table.Column<string>(type: "text", nullable: false),
                    DateAdded = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    DueDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    KnownRansomwareUse = table.Column<bool>(type: "boolean", nullable: false),
                    Cwes = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KevEntries", x => x.CveId);
                });

            migrationBuilder.CreateIndex(
                name: "IX_FeedItems_PublishedAt",
                table: "FeedItems",
                column: "PublishedAt");

            migrationBuilder.CreateIndex(
                name: "IX_FeedItems_Severity_PublishedAt",
                table: "FeedItems",
                columns: new[] { "Severity", "PublishedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_FeedItems_Source_SourceItemId",
                table: "FeedItems",
                columns: new[] { "Source", "SourceItemId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_FeedItems_Type_PublishedAt",
                table: "FeedItems",
                columns: new[] { "Type", "PublishedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_KevEntries_DateAdded",
                table: "KevEntries",
                column: "DateAdded");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "FeedItems");

            migrationBuilder.DropTable(
                name: "FeedSources");

            migrationBuilder.DropTable(
                name: "KevEntries");
        }
    }
}
