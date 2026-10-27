namespace Alastor.Core.Storage;

/// <param name="Id">Stable id, the only thing the server sends to the agent (<c>storage-cleanup</c> payload). No paths travel over the wire.</param>
/// <param name="Display">The command to run by hand, with a note after <c>#</c> that the dashboard's copy button leaves out.</param>
public sealed record CleanupDefinition(string Id, string Title, string Description, CleanupRisk Risk, string Display);

/// <summary>
/// Every cleanup the agent knows. The agent measures each one that applies to the host, and runs exactly the command
/// shown in <see cref="CleanupDefinition.Display"/> (limited to the folders and items it measured) when asked.
/// Ordered the way a person would usually go: safe caches first, then things that are only usually unused.
/// </summary>
public static class StorageCleanups
{
    public const string DockerBuildCache = "docker.build-cache";
    public const string DockerContainers = "docker.containers";
    public const string DockerImages = "docker.images";
    public const string DockerVolumes = "docker.volumes";
    public const string DockerLogs = "docker.logs";
    public const string PodmanPrune = "podman.prune";
    public const string AptCache = "apt.cache";
    public const string DnfCache = "dnf.cache";
    public const string ApkCache = "apk.cache";
    public const string AptAutoremove = "apt.autoremove";
    public const string DnfAutoremove = "dnf.autoremove";
    public const string JournalVacuum = "journal.vacuum";
    public const string RotatedLogs = "logs.rotated";
    public const string SnapRevisions = "snap.revisions";
    public const string DevCaches = "dev.caches";
    public const string CrashDumps = "crash.dumps";
    public const string OldTempFiles = "tmp.old";
    public const string AlastorScannerDbs = "alastor.scanner-dbs";
    public const string AlastorImageCache = "alastor.image-cache";
    public const string AlastorClamAv = "alastor.clamav";
    public const string AlastorAide = "alastor.aide";
    public const string AlastorLeftovers = "alastor.leftovers";

    /// <summary>What <see cref="JournalVacuum"/> shrinks the systemd journal to.</summary>
    public const string JournalKeep = "200M";

    public static readonly IReadOnlyList<CleanupDefinition> All =
    [
        new(AptCache, "APT package cache",
            "Downloaded .deb files apt keeps after installing them. apt downloads them again if it ever needs them.",
            CleanupRisk.Safe, "sudo apt-get clean"),
        new(DnfCache, "DNF package cache",
            "Downloaded packages and repository metadata. dnf fetches the metadata again on its next run.",
            CleanupRisk.Safe, "sudo dnf clean all"),
        new(ApkCache, "APK package cache",
            "Packages kept in the local apk cache (/etc/apk/cache) that no installed package needs any more.",
            CleanupRisk.Safe, "sudo apk cache clean"),
        new(JournalVacuum, "Old systemd journal entries",
            $"Archived journal files, removed oldest first until the journal is {JournalKeep}. To keep it small for good, set SystemMaxUse= in /etc/systemd/journald.conf.",
            CleanupRisk.Safe, $"sudo journalctl --vacuum-size={JournalKeep}"),
        new(RotatedLogs, "Rotated log files",
            "Old logs logrotate already rotated away (syslog.1, auth.log.2.gz, *.old). The current logs stay.",
            CleanupRisk.Safe, @"sudo find /var/log -xdev -type f ! -path '/var/log/journal/*' \( -name '*.gz' -o -name '*.xz' -o -name '*.bz2' -o -name '*.zst' -o -name '*.[0-9]' -o -name '*.[0-9].log' -o -name '*.old' \) -delete"),
        new(DockerBuildCache, "Docker build cache",
            "Layers BuildKit keeps to speed up later builds. The next build is slower once.",
            CleanupRisk.Safe, "sudo docker builder prune -a -f"),
        new(SnapRevisions, "Old snap revisions",
            "Disabled revisions snapd keeps for rollback. To keep fewer, run: sudo snap set system refresh.retain=2",
            CleanupRisk.Safe, "sudo snap remove <name> --revision=<rev>  # once per disabled revision in: snap list --all"),
        new(DevCaches, "Package manager caches in home folders",
            "pip, npm, yarn, Go build and Composer caches under /root and /home. They fill again when packages are installed or built.",
            CleanupRisk.Safe, "sudo rm -rf --one-file-system ~/.cache/pip ~/.npm/_cacache ~/.cache/yarn ~/.cache/go-build ~/.cache/composer  # for each home folder"),
        new(CrashDumps, "Crash reports and core dumps",
            "Dumps of programs that crashed (/var/crash, systemd-coredump). Only useful while debugging that crash.",
            CleanupRisk.Safe, "sudo find /var/crash /var/lib/systemd/coredump -xdev -type f -delete"),
        new(AlastorScannerDbs, "Unused CVE scanner databases",
            "The Trivy or Grype database of a scanner the policy no longer uses (both while CVE scans are off), and an old Trivy database left from an update. The agent downloads one from the server again when it needs it.",
            CleanupRisk.Safe, "sudo find /var/lib/alastor-agent/vulndb/grype /var/lib/alastor-agent/vulndb/trivy/db.old -xdev -delete  # the folder of each scanner the policy doesn't use"),
        new(AlastorImageCache, "Trivy scan cache",
            "What Trivy keeps from earlier scans (container image layers, analysis results). The database stays; the next image scan is slower.",
            CleanupRisk.Safe, "sudo find /var/lib/alastor-agent/vulndb/trivy/fanal -xdev -delete  # every folder in vulndb/trivy except db"),
        new(AlastorClamAv, "Unused ClamAV signatures",
            "The signature databases of ClamAV while malware.scanSchedule is off. The agent downloads them from the server again when scans are turned on.",
            CleanupRisk.Safe, "sudo find /var/lib/alastor-agent/clamav -xdev -delete"),
        new(AlastorLeftovers, "Alastor agent leftovers",
            "Half-finished downloads, scan output and temporary files the agent left behind when it stopped mid-way, once untouched for an hour.",
            CleanupRisk.Safe, @"sudo find /var/lib/alastor-agent -xdev -type f \( -name '*.part' -o -name 'scan-*.json' -o -name '.*.tmp' \) -mmin +60 -delete"),
        new(DockerContainers, "Stopped Docker containers",
            "Containers that have exited, with their writable layers. Anything a container wrote outside a volume is lost.",
            CleanupRisk.Caution, "sudo docker container prune -f"),
        new(DockerImages, "Unused Docker images",
            "Images no container uses, including ones only stopped containers use once those are pruned. They're pulled or built again when needed.",
            CleanupRisk.Caution, "sudo docker image prune -a -f"),
        new(DockerLogs, "Docker container logs",
            "The json-file logs of every container, emptied in place. Running containers keep logging; cap them with log-opts max-size in /etc/docker/daemon.json.",
            CleanupRisk.Caution, "sudo find /var/lib/docker/containers -type f -name '*-json.log' -exec truncate -s 0 {} +"),
        new(PodmanPrune, "Unused Podman containers and images",
            "Stopped containers, unused images and build cache. Volumes are kept.",
            CleanupRisk.Caution, "sudo podman system prune -a -f"),
        new(AptAutoremove, "Packages nothing needs any more",
            "Dependencies left behind by removed packages, and old kernels. The running kernel is never removed.",
            CleanupRisk.Caution, "sudo apt-get autoremove"),
        new(DnfAutoremove, "Packages nothing needs any more",
            "Dependencies left behind by removed packages.",
            CleanupRisk.Caution, "sudo dnf autoremove"),
        new(AlastorAide, "Unused AIDE baseline",
            "The file integrity baseline while integrity.checkSchedule is off. Turning checks on again records a new baseline, so changes made in between aren't reported.",
            CleanupRisk.Caution, "sudo find /var/lib/alastor-agent/aide -xdev -delete"),
        new(OldTempFiles, "Old temporary files",
            "Files in /tmp and /var/tmp nobody has read or changed for 10 days. A program could still expect one, so check the biggest first.",
            CleanupRisk.Caution, "sudo find /tmp /var/tmp -xdev -type f -mtime +10 -atime +10 -delete"),
        new(DockerVolumes, "Unused Docker volumes",
            "Every volume no container uses, named ones included. This deletes their data (databases, uploads) for good. Make sure nothing you need lives there.",
            CleanupRisk.Destructive, "sudo docker volume prune -a -f"),
    ];

    public static CleanupDefinition? Find(string? id) => All.FirstOrDefault(c => c.Id == id);
}
