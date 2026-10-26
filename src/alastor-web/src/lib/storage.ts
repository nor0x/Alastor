import type { CleanupRisk } from './api';

// What the common folders on a Linux server hold, so the Storage tab can say what a big folder is and whether it's
// safe to clean. Matched most specific first; `*` stands for one path segment (a user name, a container id).

export interface FolderInfo {
  /** One line on what lives there. */
  what: string;
  /** Cleanups that shrink it, by StorageCleanups id. */
  cleanups?: string[];
  /** Never delete by hand: system or application data. */
  keep?: boolean;
}

const folders: [string, FolderInfo][] = [
  ['/var/lib/docker/overlay2', { what: 'Docker image layers and container filesystems.', cleanups: ['docker.images', 'docker.containers'], keep: true }],
  ['/var/lib/docker/rootfs', { what: 'Docker image layers and container filesystems (containerd snapshotter).', cleanups: ['docker.images', 'docker.containers'], keep: true }],
  ['/var/lib/docker/containers', { what: 'Per-container state and the json-file logs.', cleanups: ['docker.logs', 'docker.containers'], keep: true }],
  ['/var/lib/docker/volumes', { what: 'Docker volumes: database files, uploads and other data containers keep.', cleanups: ['docker.volumes'], keep: true }],
  ['/var/lib/docker/buildkit', { what: 'The Docker build cache.', cleanups: ['docker.build-cache'] }],
  ['/var/lib/docker', { what: 'Docker: images, containers, volumes and build cache. Clean it with docker prune, never by deleting files.', cleanups: ['docker.images', 'docker.build-cache', 'docker.containers', 'docker.logs', 'docker.volumes'], keep: true }],
  ['/var/lib/containerd', { what: 'containerd images and snapshots (Docker, Kubernetes). Pruning Docker images shrinks it.', cleanups: ['docker.images'], keep: true }],
  ['/var/lib/containers', { what: 'Podman and Buildah images and containers (as root).', cleanups: ['podman.prune'], keep: true }],
  ['/var/lib/snapd/snaps', { what: 'Snap packages, including old revisions kept for rollback.', cleanups: ['snap.revisions'], keep: true }],
  ['/var/lib/snapd', { what: 'snapd: installed snaps and their old revisions.', cleanups: ['snap.revisions'], keep: true }],
  ['/var/lib/mysql', { what: 'MySQL/MariaDB data files. Shrink with the database itself (drop old data, purge binary logs), never by deleting files.', keep: true }],
  ['/var/lib/postgresql', { what: 'PostgreSQL data files and WAL. Free space inside the database (VACUUM, old data, replication slots).', keep: true }],
  ['/var/lib/mongodb', { what: 'MongoDB data files.', keep: true }],
  ['/var/lib/redis', { what: 'Redis snapshots (dump.rdb) and append-only files.', keep: true }],
  ['/var/lib/elasticsearch', { what: 'Elasticsearch indices. Delete old indices through its API.', keep: true }],
  ['/var/lib/apt/lists', { what: 'Package lists from the repositories. apt downloads them again on every update; they stay small.', keep: true }],
  ['/var/lib/flatpak', { what: 'Flatpak runtimes and apps.', keep: true }],
  ['/var/lib/libvirt', { what: 'Virtual machine disk images (libvirt/KVM).', keep: true }],
  ['/var/lib/lxd', { what: 'LXD containers and images.', keep: true }],
  ['/var/lib/rancher', { what: 'k3s/RKE2: container images and cluster data.', keep: true }],
  ['/var/lib/kubelet', { what: 'Kubernetes pod volumes and state.', keep: true }],
  ['/var/lib/systemd/coredump', { what: 'Core dumps of crashed programs.', cleanups: ['crash.dumps'] }],
  ['/var/lib/alastor-agent/vulndb/trivy', { what: 'Trivy\'s CVE database (db) and its cache of earlier scans and image layers.', cleanups: ['alastor.image-cache', 'alastor.scanner-dbs'] }],
  ['/var/lib/alastor-agent/vulndb', { what: 'CVE databases for Trivy and Grype, downloaded from the Alastor server, and scan output.', cleanups: ['alastor.scanner-dbs', 'alastor.image-cache', 'alastor.leftovers'] }],
  ['/var/lib/alastor-agent/clamav', { what: 'ClamAV signatures downloaded from the Alastor server for malware scans.', cleanups: ['alastor.clamav'] }],
  ['/var/lib/alastor-agent/aide', { what: 'The AIDE file integrity baseline and its config.', cleanups: ['alastor.aide'] }],
  ['/var/lib/alastor-agent', { what: 'The Alastor agent\'s state and the scanner databases it downloads. Clean it with the Alastor cleanups, never by deleting files.', cleanups: ['alastor.scanner-dbs', 'alastor.image-cache', 'alastor.clamav', 'alastor.aide', 'alastor.leftovers'], keep: true }],
  ['/var/lib/alastor', { what: 'The Alastor server: its database, keys, and the CVE and signature databases it mirrors for its agents.', keep: true }],
  ['/var/lib', { what: 'State of installed services: databases, containers, package manager data.', keep: true }],
  ['/var/log/journal', { what: 'The systemd journal. Vacuum it, or cap it with SystemMaxUse= in journald.conf.', cleanups: ['journal.vacuum'] }],
  ['/var/log', { what: 'Logs. Rotated old logs (.1, .gz) are safe to delete; the current ones are in use.', cleanups: ['logs.rotated', 'journal.vacuum'] }],
  ['/var/cache/apt', { what: 'Downloaded .deb packages apt keeps after installing.', cleanups: ['apt.cache'] }],
  ['/var/cache/dnf', { what: 'Downloaded packages and repository metadata.', cleanups: ['dnf.cache'] }],
  ['/var/cache/libdnf5', { what: 'Downloaded packages and repository metadata (dnf5).', cleanups: ['dnf.cache'] }],
  ['/var/cache/yum', { what: 'Downloaded packages and repository metadata.', cleanups: ['dnf.cache'] }],
  ['/var/cache/alastor', { what: 'Runtime files the Alastor server unpacks from its single-file binary at start. Rebuilt on the next start; stays small.' }],
  ['/var/cache', { what: 'Caches programs can rebuild: packages, man pages, fonts.' }],
  ['/var/crash', { what: 'Crash reports (apport).', cleanups: ['crash.dumps'] }],
  ['/var/backups', { what: 'Backups the system keeps of its own files (dpkg status, passwd). Usually small.' }],
  ['/var/tmp', { what: 'Temporary files kept across reboots.', cleanups: ['tmp.old'] }],
  ['/var/www', { what: 'Web sites and uploaded files.', keep: true }],
  ['/var/mail', { what: 'Local mailboxes. A full one usually means cron jobs mailing their output to root.' }],
  ['/var/spool', { what: 'Queues: mail, print and cron jobs waiting to run.' }],
  ['/var/opt', { what: 'Data of software installed under /opt.', keep: true }],
  ['/var', { what: 'Data that changes: logs, caches, databases, containers, mail.' }],
  ['/usr/lib/modules', { what: 'Kernel modules, one folder per installed kernel. Old kernels go with apt autoremove.', cleanups: ['apt.autoremove'], keep: true }],
  ['/usr/lib/firmware', { what: 'Firmware for hardware. Virtual machines need little of it, but it belongs to a package.', keep: true }],
  ['/usr/lib', { what: 'Libraries and program data from installed packages.', keep: true }],
  ['/usr/share', { what: 'Documentation, icons, locales and other package data.', keep: true }],
  ['/usr/src', { what: 'Kernel headers, one set per kernel. Old ones go with apt autoremove.', cleanups: ['apt.autoremove'], keep: true }],
  ['/usr/local', { what: 'Software installed by hand, outside the package manager.', keep: true }],
  ['/usr', { what: 'Installed programs and libraries. Shrinks only by uninstalling packages.', keep: true }],
  ['/lib/modules', { what: 'Kernel modules, one folder per installed kernel. Old kernels go with apt autoremove.', cleanups: ['apt.autoremove'], keep: true }],
  ['/boot', { what: 'Kernels and initramfs images. Old kernels go with apt autoremove.', cleanups: ['apt.autoremove'], keep: true }],
  ['/opt', { what: 'Third-party software installed in one folder each.', keep: true }],
  ['/snap', { what: 'Mount points of installed snaps (the files themselves are in /var/lib/snapd).', cleanups: ['snap.revisions'], keep: true }],
  ['/home/*/.cache', { what: 'Per-user caches. pip, yarn and Go build caches in here are cleaned with the package manager caches.', cleanups: ['dev.caches'] }],
  ['/home/*/.npm', { what: 'npm\'s download cache (_cacache) and logs.', cleanups: ['dev.caches'] }],
  ['/home/*', { what: 'A user\'s home folder.', keep: true }],
  ['/home', { what: 'Home folders of the users on this host.', keep: true }],
  ['/root/.cache', { what: 'root\'s caches. pip, yarn and Go build caches in here are cleaned with the package manager caches.', cleanups: ['dev.caches'] }],
  ['/root/.npm', { what: 'npm\'s download cache (_cacache) and logs.', cleanups: ['dev.caches'] }],
  ['/root', { what: 'The root user\'s home folder.', keep: true }],
  ['/srv', { what: 'Data served by this host (sites, FTP, repositories).', keep: true }],
  ['/tmp', { what: 'Temporary files. Usually cleared at boot; old ones can go.', cleanups: ['tmp.old'] }],
  ['/etc', { what: 'System configuration.', keep: true }],
  ['/nix', { what: 'The Nix store. Shrink it with nix-collect-garbage.', keep: true }],
  ['/mnt', { what: 'Mounted disks and network shares.', keep: true }],
  ['/media', { what: 'Mounted removable media.', keep: true }],
  ['/lost+found', { what: 'Files fsck recovered after a crash.' }],
];

const files: [RegExp, string][] = [
  [/^\/swap(file|\.img)$|\.swap$/, 'Swap space. It stays this size on purpose; shrink it only with swapoff, a smaller file and swapon.'],
  [/-json\.log$/, 'A Docker container\'s log. Cap it with log-opts max-size in /etc/docker/daemon.json.'],
  [/\.(log|out)(\.\d+)?$/, 'A log file. If it keeps growing, set up logrotate for it, or truncate it (truncate -s 0) while the program runs.'],
  [/\.(sql|dump|bak|backup|tar|tgz|tar\.gz|tar\.zst|zip|7z)$/i, 'Looks like a backup or archive. Move it off the host if you still need it.'],
  [/\.(iso|img|qcow2|vmdk|vdi|raw)$/i, 'A disk or installer image.'],
  [/\/core(\.\d+)?$|\.core$/, 'A core dump from a crashed program.'],
  [/\.(gz|xz|bz2|zst)$/, 'A compressed file, often a rotated log.'],
];

function pattern(p: string): RegExp {
  return new RegExp(`^${p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]+')}$`);
}
const compiled = folders.map(([p, info]) => [pattern(p), info] as const);

/** What a folder holds: the most specific entry that matches it or one of its parents (parents only describe "inside …"). */
export function folderInfo(path: string): FolderInfo | null {
  for (const [re, info] of compiled) if (re.test(path)) return info;
  return null;
}

export function fileInfo(path: string): string | null {
  for (const [re, what] of files) if (re.test(path)) return what;
  return null;
}

export const riskLook: Record<CleanupRisk, { tone: string; label: string; title: string }> = {
  Safe: { tone: 'ok', label: 'safe', title: 'Removes only caches and old copies that are rebuilt or downloaded again when needed' },
  Caution: { tone: 'warn', label: 'check first', title: 'Removes things that are usually unused, but someone might still want' },
  Destructive: { tone: 'bad', label: 'deletes data', title: 'Deletes data that can\'t be recovered. You\'ll be asked to type the host name.' },
};

/** Free space: warn from 80% used, bad from 90% (when the "Disk almost full" issue opens). */
export const diskTone = (percent: number) => (percent >= 90 ? 'bad' : percent >= 80 ? 'warn' : 'ok');

/** Used share the way df prints it: of the space ordinary users can have, so blocks reserved for root count as neither. */
export function usedPercent(f: { usedBytes: number; availableBytes: number }): number {
  const usable = f.usedBytes + f.availableBytes;
  return usable > 0 ? (f.usedBytes * 100) / usable : 0;
}
