using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Alastor.Server.Data;

/// <summary>
/// Provider-neutral model. Each provider has a thin subclass with its own migrations folder
/// (Data/Migrations/Sqlite, Data/Migrations/Postgres), which is the EF Core pattern for multi-provider migrations.
/// </summary>
public abstract class AlastorDbContext(DbContextOptions options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
    public DbSet<EnrollmentToken> EnrollmentTokens => Set<EnrollmentToken>();
    public DbSet<HostGroup> Groups => Set<HostGroup>();
    public DbSet<ManagedHost> Hosts => Set<ManagedHost>();
    public DbSet<HostToolStatus> ToolStatuses => Set<HostToolStatus>();
    public DbSet<HostBaselineCheck> BaselineChecks => Set<HostBaselineCheck>();
    public DbSet<HostMetricSample> MetricSamples => Set<HostMetricSample>();
    public DbSet<HostPostureSnapshot> PostureSnapshots => Set<HostPostureSnapshot>();
    public DbSet<HostIssue> Issues => Set<HostIssue>();
    public DbSet<HostLoginSource> LoginSources => Set<HostLoginSource>();
    public DbSet<StoredEvent> Events => Set<StoredEvent>();
    public DbSet<ActiveBan> Bans => Set<ActiveBan>();
    public DbSet<AllowlistEntry> Allowlist => Set<AllowlistEntry>();
    public DbSet<PolicyLayer> PolicyLayers => Set<PolicyLayer>();
    public DbSet<PolicyVersion> PolicyVersions => Set<PolicyVersion>();
    public DbSet<HostCommand> Commands => Set<HostCommand>();
    public DbSet<AuditEntry> Audit => Set<AuditEntry>();
    public DbSet<FeedItem> FeedItems => Set<FeedItem>();
    public DbSet<KevEntry> KevEntries => Set<KevEntry>();
    public DbSet<FeedSourceState> FeedSources => Set<FeedSourceState>();
    public DbSet<BlocklistSourceState> BlocklistSources => Set<BlocklistSourceState>();
    public DbSet<HostReport> HostReports => Set<HostReport>();
    public DbSet<HostVulnerability> Vulnerabilities => Set<HostVulnerability>();
    public DbSet<HostHardeningItem> HardeningItems => Set<HostHardeningItem>();
    public DbSet<NotificationChannel> NotificationChannels => Set<NotificationChannel>();
    public DbSet<AlertBucket> AlertBuckets => Set<AlertBucket>();
    public DbSet<NotificationDelivery> NotificationDeliveries => Set<NotificationDelivery>();

    protected override void ConfigureConventions(ModelConfigurationBuilder b)
    {
        // Everything is UTC. This also restores DateTimeKind.Utc on values read back from SQLite TEXT columns.
        b.Properties<DateTime>().HaveConversion<UtcConverter>();
        b.Properties<DateTime?>().HaveConversion<NullableUtcConverter>();
        b.Properties<List<string>>().HaveConversion<JsonListConverter, JsonListComparer>();
        b.Properties<Dictionary<string, string>>().HaveConversion<JsonDictConverter, JsonDictComparer>();
        b.Properties<Enum>().HaveConversion<string>().HaveMaxLength(32);
    }

    protected override void OnModelCreating(ModelBuilder m)
    {
        m.Entity<User>().HasIndex(u => u.Username).IsUnique();
        m.Entity<User>().Property(u => u.Username).HasMaxLength(64);

        m.Entity<ApiKey>().HasIndex(k => k.KeyHash).IsUnique();
        m.Entity<EnrollmentToken>().HasIndex(t => t.TokenHash).IsUnique();
        m.Entity<HostGroup>().HasIndex(g => g.Name).IsUnique();

        m.Entity<ManagedHost>(e =>
        {
            e.HasIndex(h => h.Name);
            e.HasOne(h => h.Group).WithMany().HasForeignKey(h => h.GroupId).OnDelete(DeleteBehavior.SetNull);
            e.HasMany(h => h.Tools).WithOne().HasForeignKey(t => t.HostId).OnDelete(DeleteBehavior.Cascade);
            e.Property(h => h.SshExposure).HasConversion<string>().HasMaxLength(24);
            e.Property(h => h.ObservedAddress).HasMaxLength(64);
            e.Property(h => h.TailscaleState).HasMaxLength(32);
            e.Property(h => h.TailscaleIp).HasMaxLength(64);
            e.Property(h => h.RootkitSeverity).HasConversion<int?>();
        });

        m.Entity<HostToolStatus>().HasKey(t => new { t.HostId, t.ToolId });

        m.Entity<HostReport>(e =>
        {
            e.HasKey(r => new { r.HostId, r.Kind });
            e.Property(r => r.Kind).HasMaxLength(32);
            e.Property(r => r.JobId).HasMaxLength(64);
            e.HasOne<ManagedHost>().WithMany().HasForeignKey(r => r.HostId).OnDelete(DeleteBehavior.Cascade);
        });

        m.Entity<HostVulnerability>(e =>
        {
            e.HasKey(v => v.Id);
            e.Property(v => v.VulnId).HasMaxLength(80);
            e.Property(v => v.Package).HasMaxLength(200);
            e.Property(v => v.Installed).HasMaxLength(200);
            e.Property(v => v.Fixed).HasMaxLength(400);
            e.Property(v => v.Title).HasMaxLength(256);
            e.Property(v => v.PkgType).HasMaxLength(32);
            e.Property(v => v.Path).HasMaxLength(1024);
            e.Property(v => v.Image).HasMaxLength(256);
            e.Property(v => v.Severity).HasConversion<int>(); // ordered: min-severity filters use >=
            e.HasIndex(v => v.HostId);
            e.HasIndex(v => v.VulnId);
            e.HasOne<ManagedHost>().WithMany().HasForeignKey(v => v.HostId).OnDelete(DeleteBehavior.Cascade);
        });

        m.Entity<HostHardeningItem>(e =>
        {
            e.HasKey(i => i.Id);
            e.Property(i => i.TestId).HasMaxLength(32);
            e.Property(i => i.Text).HasMaxLength(512);
            e.Property(i => i.Details).HasMaxLength(512);
            e.Property(i => i.Solution).HasMaxLength(512);
            e.HasIndex(i => i.HostId);
            e.HasIndex(i => i.TestId);
            e.HasOne<ManagedHost>().WithMany().HasForeignKey(i => i.HostId).OnDelete(DeleteBehavior.Cascade);
        });

        m.Entity<HostBaselineCheck>(e =>
        {
            e.HasKey(c => new { c.HostId, c.CheckId });
            e.Property(c => c.CheckId).HasMaxLength(64);
            e.HasIndex(c => new { c.CheckId, c.Status });
            e.HasOne<ManagedHost>().WithMany().HasForeignKey(c => c.HostId).OnDelete(DeleteBehavior.Cascade);
        });

        m.Entity<HostMetricSample>(e =>
        {
            e.HasIndex(s => new { s.HostId, s.At });
            e.HasOne<ManagedHost>().WithMany().HasForeignKey(s => s.HostId).OnDelete(DeleteBehavior.Cascade);
        });

        m.Entity<HostPostureSnapshot>(e =>
        {
            e.HasKey(s => new { s.HostId, s.Day });
            e.HasIndex(s => s.Day);
            e.HasOne<ManagedHost>().WithMany().HasForeignKey(s => s.HostId).OnDelete(DeleteBehavior.Cascade);
        });

        m.Entity<HostLoginSource>(e =>
        {
            e.HasKey(s => new { s.HostId, s.User, s.Address });
            e.Property(s => s.User).HasMaxLength(64);
            e.Property(s => s.Address).HasMaxLength(64);
            e.Property(s => s.LastMethod).HasMaxLength(48);
            e.HasOne<ManagedHost>().WithMany().HasForeignKey(s => s.HostId).OnDelete(DeleteBehavior.Cascade);
        });

        m.Entity<HostIssue>(e =>
        {
            e.Property(i => i.Rule).HasMaxLength(48);
            e.Property(i => i.Subject).HasMaxLength(128);
            e.Property(i => i.Title).HasMaxLength(256);
            e.Property(i => i.Detail).HasMaxLength(1024);
            e.Property(i => i.Tab).HasMaxLength(32);
            e.Property(i => i.AcknowledgedBy).HasMaxLength(64);
            e.Property(i => i.AckNote).HasMaxLength(512);
            e.Property(i => i.Severity).HasConversion<int>(); // ordered, like events
            e.HasIndex(i => new { i.HostId, i.Rule, i.Subject }).IsUnique();
            e.HasIndex(i => i.ResolvedAt);
            e.HasOne<ManagedHost>().WithMany().HasForeignKey(i => i.HostId).OnDelete(DeleteBehavior.Cascade);
        });

        m.Entity<StoredEvent>(e =>
        {
            // Severity is compared with >= (min-severity filters), so it must be stored as an ordered integer, not a string.
            e.Property(x => x.Severity).HasConversion<int>();
            e.HasIndex(x => x.OccurredAt);
            e.HasIndex(x => new { x.HostId, x.OccurredAt });
            e.HasIndex(x => x.Subject);
            e.HasIndex(x => new { x.Severity, x.OccurredAt });
            e.HasOne<ManagedHost>().WithMany().HasForeignKey(x => x.HostId).OnDelete(DeleteBehavior.Cascade);
        });

        m.Entity<ActiveBan>(e =>
        {
            e.HasIndex(b => new { b.HostId, b.ToolId, b.Scope, b.Target }).IsUnique();
            e.HasIndex(b => b.Target);
            e.HasOne<ManagedHost>().WithMany().HasForeignKey(b => b.HostId).OnDelete(DeleteBehavior.Cascade);
        });

        m.Entity<AllowlistEntry>().HasIndex(a => a.Target).IsUnique();

        m.Entity<PolicyLayer>(e =>
        {
            e.HasIndex(l => new { l.Scope, l.TargetId }).IsUnique();
            e.HasMany(l => l.Versions).WithOne().HasForeignKey(v => v.LayerId).OnDelete(DeleteBehavior.Cascade);
        });
        m.Entity<PolicyVersion>().HasIndex(v => new { v.LayerId, v.Version }).IsUnique();

        m.Entity<HostCommand>(e =>
        {
            e.HasIndex(c => new { c.HostId, c.Status });
            e.HasOne<ManagedHost>().WithMany().HasForeignKey(c => c.HostId).OnDelete(DeleteBehavior.Cascade);
        });

        m.Entity<AuditEntry>().HasIndex(a => a.At);

        m.Entity<FeedItem>(e =>
        {
            e.Property(x => x.Id).HasMaxLength(64);
            e.Property(x => x.Source).HasMaxLength(32);
            e.Property(x => x.Type).HasMaxLength(8);
            e.Property(x => x.SourceItemId).HasMaxLength(512);
            // Same reason as events: severity sorts and >= filters need an ordered integer.
            e.Property(x => x.Severity).HasConversion<int?>();
            e.HasIndex(x => x.PublishedAt);
            e.HasIndex(x => new { x.Type, x.PublishedAt });
            e.HasIndex(x => new { x.Severity, x.PublishedAt });
            e.HasIndex(x => new { x.Source, x.SourceItemId }).IsUnique();
        });

        m.Entity<NotificationChannel>(e =>
        {
            e.Property(x => x.Name).HasMaxLength(64);
            e.Property(x => x.Type).HasMaxLength(16);
            e.Property(x => x.MinSeverity).HasConversion<int>();
            e.Property(x => x.DigestSchedule).HasMaxLength(64);
        });
        m.Entity<AlertBucket>(e =>
        {
            e.HasKey(x => x.Key);
            e.Property(x => x.Key).HasMaxLength(300);
            e.HasIndex(x => x.UpdatedAt);
        });
        m.Entity<NotificationDelivery>(e =>
        {
            e.HasIndex(x => x.At);
            e.HasOne<NotificationChannel>().WithMany().HasForeignKey(x => x.ChannelId).OnDelete(DeleteBehavior.Cascade);
        });

        m.Entity<KevEntry>(e =>
        {
            e.HasKey(x => x.CveId);
            e.Property(x => x.CveId).HasMaxLength(32);
            e.HasIndex(x => x.DateAdded);
        });

        m.Entity<FeedSourceState>(e =>
        {
            e.HasKey(x => x.SourceId);
            e.Property(x => x.SourceId).HasMaxLength(32);
        });

        m.Entity<BlocklistSourceState>(e =>
        {
            e.HasKey(x => x.SourceId);
            e.Property(x => x.SourceId).HasMaxLength(32);
            e.Property(x => x.ContentHash).HasMaxLength(64);
        });
    }

    private sealed class UtcConverter() : ValueConverter<DateTime, DateTime>(
        v => v.Kind == DateTimeKind.Utc ? v : v.ToUniversalTime(),
        v => DateTime.SpecifyKind(v, DateTimeKind.Utc));

    private sealed class NullableUtcConverter() : ValueConverter<DateTime?, DateTime?>(
        v => v == null ? v : v.Value.Kind == DateTimeKind.Utc ? v : v.Value.ToUniversalTime(),
        v => v == null ? v : DateTime.SpecifyKind(v.Value, DateTimeKind.Utc));

    private sealed class JsonListConverter() : ValueConverter<List<string>, string>(
        v => JsonSerializer.Serialize(v, JsonSerializerOptions.Default),
        v => JsonSerializer.Deserialize<List<string>>(v, JsonSerializerOptions.Default) ?? new List<string>());

    private sealed class JsonListComparer() : ValueComparer<List<string>>(
        (a, b) => (a ?? new List<string>()).SequenceEqual(b ?? new List<string>()),
        v => v.Aggregate(0, (h, s) => HashCode.Combine(h, s.GetHashCode())),
        v => v.ToList());

    private sealed class JsonDictConverter() : ValueConverter<Dictionary<string, string>, string>(
        v => JsonSerializer.Serialize(v, JsonSerializerOptions.Default),
        v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, JsonSerializerOptions.Default) ?? new Dictionary<string, string>());

    private sealed class JsonDictComparer() : ValueComparer<Dictionary<string, string>>(
        (a, b) => (a ?? new Dictionary<string, string>()).OrderBy(kv => kv.Key).SequenceEqual((b ?? new Dictionary<string, string>()).OrderBy(kv => kv.Key)),
        v => v.Aggregate(0, (h, kv) => HashCode.Combine(h, kv.Key.GetHashCode(), kv.Value.GetHashCode())),
        v => new Dictionary<string, string>(v));
}

public sealed class SqliteAlastorDbContext(DbContextOptions<SqliteAlastorDbContext> options) : AlastorDbContext(options);

public sealed class PostgresAlastorDbContext(DbContextOptions<PostgresAlastorDbContext> options) : AlastorDbContext(options);

// Used by `dotnet ef migrations add` only.
public sealed class SqliteDesignFactory : IDesignTimeDbContextFactory<SqliteAlastorDbContext>
{
    public SqliteAlastorDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<SqliteAlastorDbContext>().UseSqlite("Data Source=design.db").Options);
}

public sealed class PostgresDesignFactory : IDesignTimeDbContextFactory<PostgresAlastorDbContext>
{
    public PostgresAlastorDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<PostgresAlastorDbContext>().UseNpgsql("Host=localhost;Database=alastor").Options);
}
