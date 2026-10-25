// Thin fetch wrapper for the SentinelVPS REST API (cookie session; see docs/architecture.md §3).

export class ApiError extends Error {
  constructor(public status: number, message: string, public body?: unknown) {
    super(message);
  }
}

let onUnauthorized: (() => void) | undefined;

/** Called when any request comes back 401, so the app can show the login form. */
export function setUnauthorizedHandler(handler: () => void) {
  onUnauthorized = handler;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  // Cookie-authenticated writes must carry the CSRF header.
  if (init.method && init.method !== 'GET') headers.set('X-Sentinel-Request', '1');
  if (init.body && !headers.has('content-type')) headers.set('content-type', 'application/json');
  const res = await fetch(path, { ...init, headers, credentials: 'same-origin' });
  if (res.status === 401 && !path.startsWith('/api/auth/login')) onUnauthorized?.();
  if (!res.ok) {
    let message = res.statusText || `HTTP ${res.status}`;
    let body: unknown;
    try {
      const problem = await res.json();
      body = problem;
      // ProblemDetails (detail/title/errors) or { error, issues } from conflict and policy responses.
      const fieldErrors = problem.errors ? Object.values(problem.errors as Record<string, string[]>).flat().join(' ') : '';
      message = problem.error ?? (fieldErrors || problem.detail || problem.title) ?? message;
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, message, body);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

export type Severity = 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
export const severities: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];

export interface Me {
  username: string;
  role: string;
  readOnly: boolean;
}

export interface FeedItem {
  id: string;
  source: string;
  sourceName: string;
  type: 'cve' | 'news';
  title: string;
  url: string;
  publishedAt: string;
  summary: string;
  severity: Severity | null;
  cvssScore: number | null;
  exploited: boolean;
  tags: string[];
  products: string[];
}

export interface FeedPage {
  items: FeedItem[];
  total: number;
  page: number;
  pageSize: number;
}

export interface FeedSource {
  id: string;
  name: string;
  kind: 'nvd' | 'kev' | 'rss';
  homepage: string;
  lastSuccessAt: string | null;
  lastAttemptAt: string | null;
  nextAttemptAt: string | null;
  consecutiveFailures: number;
  lastError: string | null;
  items: number;
}

export interface TagCount {
  tag: string;
  count: number;
}

// ---- Fleet, events, bans, policy, admin (see docs/architecture.md §3) ----

export type Capability = 'Agent' | 'Banning' | 'Blocklist' | 'Firewall' | 'Updates' | 'Vulnerabilities' | 'Hardening' | 'Network' | 'Malware';
export const capabilities: Capability[] = ['Agent', 'Banning', 'Blocklist', 'Firewall', 'Updates', 'Vulnerabilities', 'Hardening', 'Network', 'Malware'];
export type Availability = 'Available' | 'Unavailable' | 'Disabled';
export type Ownership = 'Managed' | 'Adopted' | 'NotInstalled';
export type ConfigState = 'Unknown' | 'InSync' | 'Pending' | 'Drifted' | 'Conflict' | 'Rejected';
export type PolicySync = 'in-sync' | 'pending' | 'failed';
export type CommandStatus = 'Pending' | 'Delivered' | 'Succeeded' | 'Failed' | 'Expired';
export type PolicyScope = 'Global' | 'Group' | 'Host';

export interface HostSummary {
  id: string;
  name: string;
  hostname: string;
  osPrettyName: string;
  architecture: string;
  agentVersion: string;
  isOnline: boolean;
  lastSeenAt: string | null;
  cpuPercent: number;
  memoryPercent: number;
  diskPercent: number;
  load1: number;
  groupId: string | null;
  groupName: string | null;
  tags: string[];
  activeBans: number;
  policySync: PolicySync;
  toolsRunning: number;
  toolsWithProblems: number;
  baselineScore: number | null;
  baselineFailing: number;
  pendingUpdates: number | null;
  securityUpdates: number | null;
  rebootRequired: boolean;
  vulnCritical: number | null;
  vulnHigh: number | null;
  vulnTotal: number | null;
  vulnFixable: number | null;
  hardeningIndex: number | null;
  hardeningWarnings: number | null;
  sshExposure: SshExposureLevel | null;
  sshExposureAccepted: boolean;
  tailscaleState: string | null;
}

export interface ToolStatus {
  toolId: string;
  displayName: string;
  capability: Capability;
  implemented: boolean;
  optIn: boolean;
  license: string;
  availability: Availability;
  unavailableReason: string | null;
  installed: boolean;
  version: string | null;
  running: boolean;
  ownership: Ownership;
  configState: ConfigState;
  appliedRevision: string | null;
  lastError: string | null;
  lastSuccessAt: string | null;
  warnings: string[];
  details: Record<string, string>;
  updatedAt: string | null;
}

export interface ToolApplyReport {
  toolId: string;
  success: boolean;
  state: ConfigState;
  error: string | null;
  warnings: string[];
  changes: string[];
}

export interface HostDetail {
  summary: HostSummary;
  osId: string;
  osVersion: string;
  kernelVersion: string;
  machineId: string | null;
  ipAddresses: string[];
  enrolledAt: string;
  memoryTotalBytes: number;
  memoryUsedBytes: number;
  diskTotalBytes: number;
  diskUsedBytes: number;
  load5: number;
  load15: number;
  uptimeSeconds: number;
  desiredRevision: string;
  appliedRevision: string | null;
  policyAppliedAt: string | null;
  policyApplySuccess: boolean | null;
  policyReport: { revision: string; success: boolean; appliedAtUtc: string; tools: ToolApplyReport[] } | null;
  tools: ToolStatus[];
}

export interface MetricPoint {
  at: string;
  cpu: number;
  memory: number;
  disk: number;
  load1: number;
}

export interface SecurityEvent {
  id: string;
  hostId: string | null;
  occurredAt: string;
  capability: Capability;
  severity: Severity;
  sourceTool: string;
  kind: string;
  subject: string | null;
  message: string;
  raw: string | null;
  metadata: Record<string, string>;
  /** Whether the alert pipeline sent this event to notification channels, or deduped it. */
  alert: 'None' | 'Notified' | 'Suppressed';
}

export interface EventPage {
  items: SecurityEvent[];
  nextBefore: string | null;
}

export interface Overview {
  hostsTotal: number;
  hostsOnline: number;
  hostsOffline: number;
  alerts24h: number;
  events24h: number;
  activeBans: number;
  bans24h: number;
  hostsWithToolProblems: number;
  hostsPolicyPending: number;
  hostsWithPendingSecurityUpdates: number | null;
  hostsWithHighCves: number | null;
  averageHardeningIndex: number | null;
  hostsWithPublicSsh: number | null;
  averageBaselineScore: number | null;
  hostsFailingBaselineHigh: number;
  recentAlerts: SecurityEvent[];
  topOffenders: { target: string; events: number; hosts: number }[];
}

export interface Ban {
  id: number;
  hostId: string;
  hostName: string;
  toolId: string;
  target: string;
  scope: string;
  bannedAt: string | null;
  expiresAt: string | null;
  manual: boolean;
}

export interface Command {
  id: string;
  hostId: string;
  type: string;
  payload: Record<string, string>;
  status: CommandStatus;
  createdAt: string;
  completedAt: string | null;
  resultMessage: string | null;
  createdBy: string;
}

export interface AllowlistEntry {
  id: string;
  target: string;
  note: string | null;
  createdAt: string;
  createdBy: string;
}

export interface Group {
  id: string;
  name: string;
  description: string | null;
  hostCount: number;
}

export interface PolicyLayer {
  id: string;
  scope: PolicyScope;
  targetId: string | null;
  targetName: string;
  currentVersion: number;
  updatedAt: string | null;
  updatedBy: string | null;
}

export interface PolicyVersion {
  version: number;
  comment: string | null;
  createdAt: string;
  createdBy: string;
}

export interface PolicyLayerDetail {
  layer: PolicyLayer | null;
  yaml: string;
  versions: PolicyVersion[];
}

export interface PolicyIssue {
  level: 'Warning' | 'Error';
  path: string;
  message: string;
  line: number | null;
}

export interface ScheduleInfo {
  path: string;
  schedule: string;
  kind: 'off' | 'cron' | 'interval';
  isDefault: boolean;
  nextRunsHostLocal: string[];
}

export interface PolicyPreview {
  issues: PolicyIssue[];
  effectiveYaml: string | null;
  revision: string | null;
  fail2BanConfig: string | null;
  schedules: ScheduleInfo[] | null;
}

export interface EnrollmentToken {
  id: string;
  note: string | null;
  groupId: string | null;
  tags: string[];
  createdAt: string;
  expiresAt: string;
  consumedAt: string | null;
  consumedByHostId: string | null;
  createdBy: string;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdBy: string;
}

export interface AuditEntry {
  id: number;
  at: string;
  actor: string;
  action: string;
  target: string | null;
  details: string | null;
}

export interface About {
  product: string;
  version: string;
  license: string;
  repository: string | null;
  bundledTools: { id: string; name: string; capability: string; license: string; homepage: string; implemented: boolean; optIn: boolean; description: string }[];
  notes: string[];
}

/** Error text for a failed write: validation problems list their fields, conflicts carry `error`. */
export interface PendingUpdate {
  name: string;
  installed: string | null;
  candidate: string;
  source: string | null;
  /** null when the package manager can't tell (Alpine). */
  security: boolean | null;
}

export interface UpdateApplyResult {
  atUtc: string;
  success: boolean;
  upgraded: string[];
  error: string | null;
  logTail: string;
}

export interface UpdatesReport {
  manager: string;
  packages: PendingUpdate[];
  rebootRequired: boolean;
  rebootPackages: string[];
  lastApply: UpdateApplyResult | null;
  pending: number;
  security: number | null;
}

export interface HostUpdates {
  hostId: string;
  hostName: string;
  report: UpdatesReport | null;
  lastCheckSucceeded: boolean | null;
  lastCheckError: string | null;
  checkedAt: string | null;
  schedules: { key: string; value: string; isDefault: boolean }[];
}

export interface FleetUpdatesRow {
  hostId: string;
  name: string;
  online: boolean;
  groupName: string | null;
  pending: number | null;
  security: number | null;
  rebootRequired: boolean;
  checkedAt: string | null;
  lastAppliedAt: string | null;
  lastApplySucceeded: boolean | null;
  lastCheckError: string | null;
}

export type FixState = 'Fixable' | 'NoFix' | 'WontFix' | 'Unknown';

export interface VulnFinding {
  id: string;
  package: string;
  installed: string;
  fixed: string | null;
  severity: Severity;
  cvss: number | null;
  fix: FixState;
  title: string | null;
  pkgType: string;
  path: string | null;
  accepted: boolean;
  kev: boolean;
  ransomware: boolean;
  firstSeenAt: string;
}

export interface HostVulnerabilities {
  hostId: string;
  hostName: string;
  scanner: {
    setting: string;
    active: string | null;
    version: string | null;
    availability: Availability | null;
    reason: string | null;
    languagePackages: boolean;
    ignorePackages: string[];
    alertSeverity: string;
  };
  os: string | null;
  dbUpdatedAt: string | null;
  ignored: Record<string, number>;
  truncated: boolean;
  scannedAt: string | null;
  lastScanSucceeded: boolean | null;
  lastScanError: string | null;
  lastAttemptAt: string | null;
  schedule: { key: string; value: string; isDefault: boolean };
  findings: VulnFinding[];
}

export interface VulnDbStatus {
  scanner: string;
  available: boolean;
  downloadsEnabled: boolean;
  etag: string | null;
  builtAt: string | null;
  fetchedAt: string | null;
  size: number;
  lastCheckedAt: string | null;
  lastError: string | null;
  lastRequestedAt: string | null;
  source: string;
}

export interface FleetCve {
  id: string;
  severity: Severity;
  cvss: number | null;
  title: string | null;
  kev: boolean;
  ransomware: boolean;
  fixable: boolean;
  hostCount: number;
  packages: string[];
  hosts: { id: string; name: string }[];
}

export interface FleetVulnHost {
  hostId: string;
  name: string;
  online: boolean;
  groupName: string | null;
  critical: number | null;
  high: number | null;
  total: number | null;
  fixable: number | null;
  kev: number;
  scannedAt: string | null;
  scanner: string | null;
  error: string | null;
  availability: Availability | null;
}

export interface FleetVulnerabilities {
  cves: FleetCve[];
  totalCves: number;
  hosts: FleetVulnHost[];
  databases: VulnDbStatus[];
}

/** NVD for CVEs, GitHub for GHSA advisories, OSV for distro advisories (ALSA, DSA, …). */
export function vulnUrl(id: string): string {
  if (id.startsWith('CVE-')) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (id.startsWith('GHSA-')) return `https://github.com/advisories/${id}`;
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

export type LynisItemKind = 'Warning' | 'Suggestion';

export interface HardeningItem {
  testId: string;
  kind: LynisItemKind;
  category: string;
  text: string;
  details: string | null;
  solution: string | null;
  accepted: boolean;
  firstSeenAt: string;
}

export interface HostHardening {
  hostId: string;
  hostName: string;
  tool: { version: string | null; availability: string | null; reason: string | null; ownership: string | null; installed: boolean };
  hardeningIndex: number | null;
  lynisVersion: string | null;
  testsExecuted: number | null;
  auditedAt: string | null;
  lastAuditSucceeded: boolean | null;
  lastAuditError: string | null;
  lastAttemptAt: string | null;
  schedule: { key: string; value: string; isDefault: boolean };
  resolvedSinceLast: string[];
  items: HardeningItem[];
}

export interface FleetHardeningHost {
  hostId: string;
  name: string;
  online: boolean;
  groupName: string | null;
  hardeningIndex: number | null;
  warnings: number | null;
  suggestions: number | null;
  auditedAt: string | null;
  error: string | null;
  availability: string | null;
}

export interface FleetHardeningItem {
  testId: string;
  kind: LynisItemKind;
  category: string;
  text: string;
  solution: string | null;
  hostCount: number;
  hosts: { id: string; name: string }[];
}

export interface FleetHardening {
  averageIndex: number | null;
  hosts: FleetHardeningHost[];
  items: FleetHardeningItem[];
}

/** CISOfy documents every Lynis control at a stable URL. */
export function lynisUrl(testId: string): string {
  return `https://cisofy.com/lynis/controls/${encodeURIComponent(testId)}/`;
}

export type SshExposureLevel = 'Public' | 'PossiblyPublic' | 'Restricted' | 'PrivateOnly' | 'TailnetOnly' | 'LocalOnly' | 'NotListening' | 'NoSsh' | 'Unknown';
export type FirewallSshVerdict = 'NoFirewall' | 'OpenToAnywhere' | 'Restricted' | 'Blocked' | 'Unknown';
export type AddressKind = 'Public' | 'Private' | 'Tailnet' | 'Loopback' | 'LinkLocal' | 'Other';

export interface TailscaleInfo {
  version: string | null;
  backendState: string;
  ips: string[];
  dnsName: string | null;
  tailnet: string | null;
  peersTotal: number;
  peersOnline: number;
  sshEnabled: boolean | null;
  keyExpiry: string | null;
  health: string[];
  running: boolean;
}

export interface SshExposure {
  level: SshExposureLevel;
  reachableOn: string[];
  reasons: string[];
  accepted: boolean;
}

export interface NetworkReport {
  tailscale: TailscaleInfo | null;
  tailscaleError: string | null;
  addresses: { interface: string; address: string; prefixLength: number; kind: AddressKind }[];
  ssh: { ports: number[]; passwordAuthentication: boolean; permitRootLogin: string; listeners: { address: string; port: number }[]; error: string | null } | null;
  firewall: { tool: string | null; verdict: FirewallSshVerdict; detail: string };
  exposure: SshExposure;
}

export interface HostNetwork {
  hostId: string;
  hostName: string;
  report: NetworkReport | null;
  exposure: SshExposure | null;
  observedAddress: string | null;
  allowPublicSsh: boolean;
  tailnetAllowlisted: boolean;
  checkedAt: string | null;
  lastCheckSucceeded: boolean | null;
  lastCheckError: string | null;
  lastAttemptAt: string | null;
  schedule: { key: string; value: string; isDefault: boolean };
}

export interface FleetNetworkRow {
  hostId: string;
  name: string;
  online: boolean;
  groupName: string | null;
  exposure: SshExposureLevel | null;
  accepted: boolean;
  passwordAuth: boolean | null;
  ports: number[];
  firewallTool: string | null;
  firewall: FirewallSshVerdict | null;
  tailscaleState: string | null;
  tailscaleIp: string | null;
  tailscaleSsh: boolean | null;
  checkedAt: string | null;
  error: string | null;
}

export interface BlocklistList {
  id: string;
  name: string;
  homepage: string;
  description: string;
  terms: string;
  usedBy: string[];
  entries: number;
  ipv4Addresses: number;
  skipped: number;
  lastSuccessAt: string | null;
  lastChangedAt: string | null;
  lastAttemptAt: string | null;
  nextAttemptAt: string | null;
  lastError: string | null;
}

export interface HostBlocklist {
  hostId: string;
  name: string;
  online: boolean;
  wanted: boolean;
  active: boolean;
  backend: string | null;
  entries: string | null;
  lists: string | null;
  dropped: number | null;
  configState: ConfigState | null;
  lastError: string | null;
  lastAppliedAt: string | null;
}

export interface BlocklistOverview {
  fetchingEnabled: boolean;
  refreshInterval: string;
  lists: BlocklistList[];
  hosts: HostBlocklist[];
}

export interface BlocklistLookup {
  target: string;
  reserved: boolean;
  allowlisted: boolean;
  lists: string[];
  extra: string[];
}

export type ChannelType = 'email' | 'webhook' | 'ntfy';

export interface ChannelConfig {
  smtpHost?: string | null;
  smtpPort?: number | null;
  smtpSecurity?: 'starttls' | 'ssl' | 'none' | null;
  smtpUsername?: string | null;
  smtpPassword?: string | null;
  from?: string | null;
  to?: string[] | null;
  url?: string | null;
  format?: 'json' | 'slack' | 'discord' | null;
  secret?: string | null;
  ntfyServer?: string | null;
  topic?: string | null;
  token?: string | null;
}

export interface NotificationChannel {
  id: string;
  name: string;
  type: ChannelType;
  enabled: boolean;
  minSeverity: Severity;
  capabilities: Capability[];
  immediate: boolean;
  digestSchedule: string;
  nextDigestAt: string | null;
  config: ChannelConfig;
  secretsSet: { smtpPassword: boolean; secret: boolean; token: boolean };
  createdAt: string;
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
}

export interface NotificationDelivery {
  id: number;
  channelId: string;
  channelName: string;
  at: string;
  kind: 'alert' | 'digest' | 'test';
  title: string;
  eventCount: number;
  success: boolean;
  attempts: number;
  error: string | null;
}

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : 'Something went wrong.';
}
