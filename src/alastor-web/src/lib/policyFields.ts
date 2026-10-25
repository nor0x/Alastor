// The policy keys the form view edits. Everything else stays in the YAML view. Paths and bounds mirror
// Alastor.Core (PolicyDocument, AgentTimings.Bounds, Schedule); the server re-validates every save.

export type FieldKind = 'duration' | 'schedule' | 'int';

export interface PolicyField {
  path: string[];
  label: string;
  kind: FieldKind;
  help: string;
  placeholderDefault?: string;
}

export interface FieldSection {
  title: string;
  description: string;
  fields: PolicyField[];
}

export const fieldSections: FieldSection[] = [
  {
    title: 'Banning defaults',
    description: 'Applied to every jail unless the jail sets its own value.',
    fields: [
      { path: ['banning', 'defaults', 'bantime'], label: 'Ban time', kind: 'duration', help: 'How long an address stays banned. "permanent" never expires.' },
      { path: ['banning', 'defaults', 'findtime'], label: 'Find time', kind: 'duration', help: 'Window in which failures are counted.' },
      { path: ['banning', 'defaults', 'maxretry'], label: 'Max retries', kind: 'int', help: 'Failures within the find time that trigger a ban.' },
      { path: ['banning', 'defaults', 'bantimeMaxtime'], label: 'Longest repeat ban', kind: 'duration', help: 'Upper bound when repeat offenders get longer bans.' },
      { path: ['banning', 'manualBantime'], label: 'Manual ban time', kind: 'duration', help: 'For bans issued from this dashboard.' },
    ],
  },
  {
    title: 'Scheduled jobs',
    description: '"every 6h", a cron expression like "0 3 * * *" (host-local time), or "off".',
    fields: [
      { path: ['updates', 'checkSchedule'], label: 'Check for security updates', kind: 'schedule', help: 'Counts pending security updates.', placeholderDefault: 'every 6h' },
      { path: ['updates', 'applySchedule'], label: 'Auto-install security updates', kind: 'schedule', help: '"off" reports only; you apply with "Apply now".', placeholderDefault: 'off' },
      { path: ['vulnerabilities', 'scanSchedule'], label: 'CVE scan (Trivy/Grype)', kind: 'schedule', help: 'Scans the installed package inventory.', placeholderDefault: '0 3 * * *' },
      { path: ['blocklists', 'refreshSchedule'], label: 'Blocklist refresh', kind: 'schedule', help: 'How often agents ask the server for a newer blocklist (a cheap conditional request).', placeholderDefault: 'every 1h' },
      { path: ['baseline', 'checkSchedule'], label: 'Security baseline checks', kind: 'schedule', help: 'Also runs on agent start, after policy changes, and on "Re-check now".', placeholderDefault: 'every 1h' },
      { path: ['hardening', 'auditSchedule'], label: 'Hardening audit (Lynis)', kind: 'schedule', help: 'Produces the hardening index and checklist.', placeholderDefault: '0 5 * * 0' },
      { path: ['network', 'checkSchedule'], label: 'SSH exposure & Tailscale check', kind: 'schedule', help: 'Reads listening services, addresses and the firewall; flags public ports outside network.allowPublicPorts.', placeholderDefault: 'every 1h' },
      { path: ['malware', 'scanSchedule'], label: 'Malware scan (ClamAV)', kind: 'schedule', help: 'Opt-in. Scans web roots and upload directories.', placeholderDefault: 'off' },
      { path: ['agent', 'scheduleSpread'], label: 'Per-host spread', kind: 'duration', help: 'Hosts start scheduled jobs at a stable offset up to this long, so the fleet doesn\'t scan in the same minute (0–12h).', placeholderDefault: '30m' },
    ],
  },
  {
    title: 'Agent timings',
    description: 'How often agents report and re-check. Shorter is more responsive; longer is lighter.',
    fields: [
      { path: ['agent', 'heartbeatInterval'], label: 'Heartbeat', kind: 'duration', help: 'Metrics, tool health, and polling for policy and commands (10s–1h). Offline detection follows this.', placeholderDefault: '60s' },
      { path: ['agent', 'driftCheckInterval'], label: 'Drift check', kind: 'duration', help: 'Re-verify tool config and daemons without a policy change (1m–1d).', placeholderDefault: '5m' },
      { path: ['agent', 'eventFlushInterval'], label: 'Event flush', kind: 'duration', help: 'Ship new bans and failures to the server (1s–10m).', placeholderDefault: '5s' },
      { path: ['agent', 'banSnapshotInterval'], label: 'Ban list resync', kind: 'duration', help: 'Full ban-list snapshot (30s–1d).', placeholderDefault: '5m' },
      { path: ['agent', 'offlineGracePeriod'], label: 'Offline grace period', kind: 'duration', help: 'Remove server-pushed firewall state after losing the server this long. "permanent" keeps it.', placeholderDefault: '24h' },
    ],
  },
];
