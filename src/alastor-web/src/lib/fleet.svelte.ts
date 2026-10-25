import { api, type Group, type HostSummary } from './api';
import { on } from './live.svelte';

// Hosts and groups are small and used everywhere (names in event lists, pickers, filters), so they are
// loaded once and kept fresh from hub hints.

export const fleet = $state<{ hosts: HostSummary[]; groups: Group[]; loaded: boolean; error: string }>({ hosts: [], groups: [], loaded: false, error: '' });

/** id -> display name. Svelte can't export $derived from a module, so this is a reactive function. */
export function hostNames(): Record<string, string> {
  return Object.fromEntries(fleet.hosts.map((h) => [h.id, h.name]));
}

let inflight: Promise<void> | undefined;

export function refreshFleet(): Promise<void> {
  return (inflight ??= Promise.all([api<HostSummary[]>('/api/hosts'), api<Group[]>('/api/groups')])
    .then(([hosts, groups]) => {
      fleet.hosts = hosts;
      fleet.groups = groups;
      fleet.loaded = true;
      fleet.error = '';
    })
    .catch((e) => {
      fleet.error = e instanceof Error ? e.message : 'Failed to load hosts';
    })
    .finally(() => (inflight = undefined)));
}

let wired = false;
export function wireFleet() {
  if (wired) return;
  wired = true;
  // hostUpdated carries a full summary from heartbeats, or just {id, isOnline} from the presence sweep.
  on('hostUpdated', (h: Partial<HostSummary> & { id: string }) => {
    const i = fleet.hosts.findIndex((x) => x.id === h.id);
    if (i >= 0 && 'name' in h) fleet.hosts[i] = h as HostSummary;
    else if (i >= 0) fleet.hosts[i] = { ...fleet.hosts[i], ...h };
    else refreshFleet();
  });
  on('bansChanged', () => refreshFleet());
  on('policyChanged', () => refreshFleet());
}
