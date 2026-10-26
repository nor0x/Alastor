import { isMap, isScalar, parseDocument } from 'yaml';
import { api, type PolicyLayerDetail, type PolicyVersion, type Severity } from './api';

// Security baseline (see Alastor.Core/Baseline). Fixes and accepted risks are policy keys, so every button here
// is a small edit of one policy layer: read the layer's YAML, set or remove one key, save it as a new version.

export type CheckStatus = 'Pass' | 'Fail' | 'Unknown' | 'NotApplicable';
export type BaselineCategory = 'Ssh' | 'Firewall' | 'Updates' | 'Kernel' | 'Accounts' | 'System';

export interface BaselineCheck {
  id: string;
  title: string;
  category: BaselineCategory;
  severity: Severity;
  why: string;
  expected: string;
  fix: 'Policy' | 'Manual';
  remediation: string;
  policyPath: string[];
  policyValue: string;
  status: CheckStatus | null;
  actual: string | null;
  detail: string | null;
  commands: string[];
  enforced: boolean;
  accepted: boolean;
  updatedAt: string | null;
  failingSince: string | null;
}

export interface HostBaseline {
  hostId: string;
  hostName: string;
  groupId: string | null;
  score: number | null;
  checkedAt: string | null;
  policyRevision: string | null;
  checks: BaselineCheck[];
}

export interface BaselineFleetCheck {
  check: BaselineCheck;
  passing: number;
  failing: number;
  accepted: number;
  unknown: number;
  notApplicable: number;
  enforced: number;
  failingHosts: { id: string; name: string; actual: string; commands: string[] }[];
}

/** Commands that fix a check by hand, and the hosts they're for (empty on a host's own page). */
export interface CommandGroup {
  hosts: { id: string; name: string }[];
  commands: string[];
}

/** Failing hosts grouped by identical commands, so a fleet on one distribution shows one block. */
export function commandGroups(fc: BaselineFleetCheck): CommandGroup[] {
  const groups = new Map<string, CommandGroup>();
  for (const h of fc.failingHosts) {
    if (!h.commands.length) continue;
    const key = h.commands.join('\n');
    const g = groups.get(key) ?? { hosts: [], commands: h.commands };
    g.hosts.push({ id: h.id, name: h.name });
    groups.set(key, g);
  }
  return [...groups.values()];
}

export interface BaselineFleetHost {
  id: string;
  name: string;
  groupId: string | null;
  groupName: string | null;
  isOnline: boolean;
  score: number | null;
  checkedAt: string | null;
  failing: number;
  failingHighOrCritical: number;
}

export interface BaselineFleet {
  averageScore: number | null;
  hostsReported: number;
  hostsTotal: number;
  hosts: BaselineFleetHost[];
  checks: BaselineFleetCheck[];
}

export const categoryLabels: Record<BaselineCategory, string> = {
  Ssh: 'SSH',
  Firewall: 'Firewall',
  Updates: 'Updates',
  Kernel: 'Kernel',
  Accounts: 'Accounts & files',
  System: 'System',
};

export const severityRank: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };

/** How much a check counts toward the score (BaselineScore.Weight on the server). */
export const severityWeight: Record<Severity, number> = { Critical: 10, High: 6, Medium: 3, Low: 1, Info: 0 };
export const weightsText = 'critical 10, high 6, medium 3, low 1';
export const severityHelp = (s: Severity) => `${s} severity: weighs ${severityWeight[s]} in the score (${weightsText})`;

/** Score tone: the number is always shown next to it, so colour is never the only signal. */
export function scoreTone(score: number | null): 'ok' | 'warn' | 'bad' | 'muted' {
  if (score === null) return 'muted';
  return score >= 90 ? 'ok' : score >= 70 ? 'warn' : 'bad';
}

export type Layer = { scope: 'global' } | { scope: 'group'; id: string } | { scope: 'host'; id: string };

/** A choice in the "apply fix" dialog: which policy layer gets the key. */
export interface ScopeOption {
  key: string;
  layer: Layer;
  label: string;
  help: string;
}

export const layerEndpoint = (l: Layer) => (l.scope === 'global' ? '/api/policies/global' : `/api/policies/${l.scope}/${l.id}`);
export const layerHref = (l: Layer) => (l.scope === 'global' ? '/policies/global' : `/policies/${l.scope}/${l.id}`);

/** The key accepts a check's risk (manual and policy checks alike). */
export const ignorePath = (c: BaselineCheck) => ['baseline', 'mitigations', c.id];

/** The value one layer sets at `path`, or undefined. */
export async function layerValue(layer: Layer, path: string[]): Promise<unknown> {
  const d = await api<PolicyLayerDetail>(layerEndpoint(layer));
  const v = parseDocument(d.yaml || '{}').getIn(path);
  return v === null ? undefined : v;
}

/**
 * Sets (or with `value === undefined` removes) one key in a policy layer and saves a new version. Comments and
 * the rest of the layer stay as they are; parents emptied by a removal are dropped.
 */
export async function setLayerKey(layer: Layer, path: string[], value: string | boolean | string[] | undefined, comment: string): Promise<PolicyVersion> {
  const current = await api<PolicyLayerDetail>(layerEndpoint(layer));
  const d = parseDocument(current.yaml || '');
  if (d.errors.length) throw new Error('This policy layer has YAML errors. Fix it in the policy editor first.');
  if (value === undefined) {
    d.deleteIn(path);
    for (let i = path.length - 1; i > 0; i--) {
      const parent = d.getIn(path.slice(0, i));
      if (isMap(parent) && parent.items.length === 0) d.deleteIn(path.slice(0, i));
      else break;
    }
  } else {
    if (d.contents === null || !isMap(d.contents)) d.contents = d.createNode({}) as unknown as typeof d.contents;
    const node = d.createNode(value);
    if (isScalar(node) && typeof node.value === 'string' && /^(off|on|yes|no|true|false|y|n)$/i.test(node.value)) node.type = 'QUOTE_DOUBLE';
    d.setIn(path, node);
  }
  const text = isMap(d.contents) && d.contents.items.length === 0 ? '' : d.toString();
  return api<PolicyVersion>(layerEndpoint(layer), { method: 'PUT', body: JSON.stringify({ yaml: text, comment }) });
}

/** The value a policy-fix check needs: "true" for the sshd jail is a boolean, "apply" stays a string. */
export const fixValue = (c: BaselineCheck): string | boolean => (c.policyValue === 'true' ? true : c.policyValue);

/**
 * Undo "apply" or "ignore" on a host: drop the host's own key, and if a lower layer (group or global) still sets
 * apply/ignore, override it with "report" so this host goes back to reporting only.
 */
export async function resetOnHost(c: BaselineCheck, hostId: string, groupId: string | null, comment: string): Promise<PolicyVersion> {
  const path = ignorePath(c);
  const lower = (groupId ? await layerValue({ scope: 'group', id: groupId }, path) : undefined) ?? (await layerValue({ scope: 'global' }, path));
  const inherited = typeof lower === 'string' && lower !== 'report';
  return setLayerKey({ scope: 'host', id: hostId }, path, inherited ? 'report' : undefined, comment);
}
