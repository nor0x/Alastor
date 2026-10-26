<script lang="ts">
  import { api, errorText, type Command, type FleetSoftwareRow, type SoftwareHostRow } from '../lib/api';
  import type { CommandGroup } from '../lib/baseline';
  import FixCommands from '../lib/FixCommands.svelte';
  import { refreshOn } from '../lib/live.svelte';
  import { route } from '../lib/router.svelte';
  import { canWrite } from '../lib/session.svelte';
  import { toast } from '../lib/toast.svelte';
  import { confirm } from '../lib/ui/confirm.svelte';
  import VulnBadge from '../lib/ui/VulnBadge.svelte';

  const params = new URLSearchParams(route.search);
  let rows = $state<FleetSoftwareRow[] | null>(null);
  let error = $state('');
  let all = $state(params.get('all') === '1');
  let q = $state(params.get('q') ?? '');
  let onlyUpdates = $state(params.get('updates') === '1');
  let onlyVulns = $state(params.get('cves') === '1');
  let limit = $state(100);
  let expanded = $state<string | null>(null);
  let hosts = $state<Record<string, SoftwareHostRow[]>>({});
  let upgrading = $state<string | null>(null);

  async function load() {
    try {
      rows = await api<FleetSoftwareRow[]>(`/api/software${all ? '?all=true' : ''}`);
      error = '';
      if (expanded) loadHosts(expanded);
    } catch (e) {
      error = errorText(e);
    }
  }

  async function loadHosts(name: string) {
    try {
      hosts = { ...hosts, [name]: await api<SoftwareHostRow[]>(`/api/software/${encodeURIComponent(name)}/hosts`) };
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  $effect(() => {
    void all;
    load();
  });
  $effect(() => refreshOn(['hostUpdated'], load, 60_000));

  $effect(() => {
    const p = new URLSearchParams();
    if (all) p.set('all', '1');
    if (q.trim()) p.set('q', q.trim());
    if (onlyUpdates) p.set('updates', '1');
    if (onlyVulns) p.set('cves', '1');
    const s = p.toString();
    history.replaceState(null, '', s ? `/software?${s}` : '/software');
  });

  const filtered = $derived.by(() => {
    const needle = q.trim().toLowerCase();
    return (rows ?? []).filter((r) =>
      (!needle || r.name.toLowerCase().includes(needle)) && (!onlyUpdates || r.outdated > 0) && (!onlyVulns || r.vulnerableHosts > 0));
  });
  const visible = $derived(filtered.slice(0, limit));
  const outdated = $derived((rows ?? []).filter((r) => r.outdated > 0));
  const vulnerable = $derived((rows ?? []).filter((r) => r.vulnerableHosts > 0));
  const exploited = $derived((rows ?? []).filter((r) => r.exploited));

  function toggle(name: string) {
    expanded = expanded === name ? null : name;
    if (expanded && !hosts[expanded]) loadHosts(expanded);
  }

  // Hosts that run the same command share one entry, like the baseline's fix-by-hand lists.
  function upgradeGroups(list: SoftwareHostRow[]): CommandGroup[] {
    const groups = new Map<string, CommandGroup>();
    for (const h of list.filter((h) => h.candidate && h.upgradeCommand)) {
      const g = groups.get(h.upgradeCommand!) ?? { hosts: [], commands: [h.upgradeCommand!] };
      g.hosts.push({ id: h.hostId, name: h.name });
      groups.set(h.upgradeCommand!, g);
    }
    return [...groups.values()];
  }

  async function upgradeAll(name: string, list: SoftwareHostRow[]) {
    const targets = list.filter((h) => h.candidate);
    const offline = targets.filter((h) => !h.online).length;
    const ok = await confirm(`Upgrade ${name} on ${targets.length} host${targets.length === 1 ? '' : 's'}?`,
      `Each agent upgrades ${name} with its own package manager, keeping locally changed config files. Services may restart; hosts are never rebooted.` +
      (offline ? ` ${offline} offline host${offline === 1 ? ' runs' : 's run'} it when the agent reconnects.` : '') +
      ' To see exactly what changes on one host first, use Upgrade on its Software tab.',
      { confirmLabel: 'Upgrade all' });
    if (!ok) return;
    upgrading = name;
    try {
      const cmds = await api<Command[]>('/api/software/upgrade', { method: 'POST', body: JSON.stringify({ package: name, hostIds: targets.map((h) => h.hostId) }) });
      toast(`Upgrade of ${name} queued on ${cmds.length} host${cmds.length === 1 ? '' : 's'}. Each host's Software tab shows the result.`);
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      upgrading = null;
    }
  }
</script>

<div class="page-head">
  <div>
    <h1>Software</h1>
    <p class="sub">Installed packages across the fleet, with available updates and known vulnerabilities from each host's CVE scan and OSV.dev.</p>
  </div>
  <div class="seg" role="group" aria-label="Which packages">
    <button class:on={!all} aria-pressed={!all} onclick={() => (all = false)} title="Installed on purpose on at least one host, or with an update or known CVE somewhere">Notable</button>
    <button class:on={all} aria-pressed={all} onclick={() => (all = true)}>All packages</button>
  </div>
</div>

{#if error}<div class="banner bad" role="alert"><p>{error}</p></div>{/if}

{#if rows}
  <section class="card summary-card" aria-label="Software summary">
    <div class="ledger strip">
      <div><span class="figure-label">{all ? 'Packages' : 'Notable packages'}</span><span class="figure-value">{rows.length}</span></div>
      <div><span class="figure-label" title="Packages with a newer version in the repositories on at least one host">With updates</span><span class="figure-value">{outdated.length}</span></div>
      <div><span class="figure-label" title="Packages with a known vulnerability on at least one host">With known CVEs</span><span class="figure-value" class:bad={vulnerable.length > 0}>{vulnerable.length}</span></div>
      <div><span class="figure-label" title="Packages with a CVE in CISA's Known Exploited Vulnerabilities catalog">Exploited</span><span class="figure-value" class:bad={exploited.length > 0}>{exploited.length}</span></div>
    </div>
  </section>
{/if}

<div class="filterbar">
  <input class="field grow" type="search" placeholder="Package name…" bind:value={q} aria-label="Search packages" />
  <label class="check"><input type="checkbox" bind:checked={onlyUpdates} /> Has update</label>
  <label class="check"><input type="checkbox" bind:checked={onlyVulns} /> Has CVEs</label>
</div>

<div class="card">
  {#if !rows}
    <div class="skeleton-block"></div>
  {:else if rows.length === 0}
    <div class="empty">No host has reported its installed software yet. Agents collect it on startup; older agents need an update first.</div>
  {:else if filtered.length === 0}
    <div class="empty">No package matches these filters.</div>
  {:else}
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>Package</th>
            <th class="num" title="Hosts with the package installed; in brackets, how many installed it on purpose">Hosts</th>
            <th class="hide-sm" title="Installed versions and how many hosts run each">Versions</th>
            <th class="num" title="Hosts where a newer version is available; red: a security update">Updates</th>
            <th title="Known vulnerabilities in the installed versions, counted once per CVE">CVEs</th>
          </tr>
        </thead>
        <tbody>
          {#each visible as r (r.name)}
            <tr class="row" class:open={expanded === r.name}>
              <td>
                <button class="linkish mono" onclick={() => toggle(r.name)} aria-expanded={expanded === r.name}>{r.name}</button>
              </td>
              <td class="num">{r.hosts}{#if r.manualHosts && r.manualHosts !== r.hosts}<span class="muted small"> ({r.manualHosts})</span>{/if}</td>
              <td class="hide-sm">
                <span class="versions">
                  {#each r.versions.slice(0, 4) as v (v.version)}<span class="pill tag mono" title="{v.hosts} host{v.hosts === 1 ? '' : 's'}">{v.version}{#if r.versions.length > 1}{` ×${v.hosts}`}{/if}</span>{/each}
                  {#if r.versions.length > 4}<span class="muted small">+{r.versions.length - 4} more</span>{/if}
                </span>
              </td>
              <td class="num">
                {#if r.outdated}<span class:bad-text={r.securityOutdated > 0} title={r.securityOutdated ? `${r.securityOutdated} with a security update` : undefined}>{r.outdated}</span>
                {:else}<span class="nil" aria-label="none"></span>{/if}
              </td>
              <td>
                {#if r.vulnerableHosts}
                  <span class="cves">
                    <VulnBadge critical={r.critical} high={r.high} total={r.cves} />
                    <span class="muted small" title="Hosts with at least one of them">on {r.vulnerableHosts}</span>
                    {#if r.exploited}<span class="pill bad" title="In CISA's Known Exploited Vulnerabilities catalog">exploited</span>{/if}
                  </span>
                {:else}<span class="nil" aria-label="none known"></span>{/if}
              </td>
            </tr>
            {#if expanded === r.name}
              <tr class="detail">
                <td colspan="5">
                  {#if !hosts[r.name]}
                    <div class="skeleton-block small-skel"></div>
                  {:else}
                    {@const list = hosts[r.name]}
                    {@const groups = upgradeGroups(list)}
                    <div class="table-wrap">
                      <table class="table inner">
                        <thead><tr><th>Host</th><th>Installed</th><th>Available</th><th title="Known vulnerabilities in the installed version">CVEs</th></tr></thead>
                        <tbody>
                          {#each list as h (h.hostId)}
                            <tr>
                              <td>
                                <a href="/hosts/{h.hostId}?tab=software">{h.name}</a>
                                {#if !h.online}<span class="pill muted">offline</span>{/if}
                                {#if h.groupName}<span class="pill tag">{h.groupName}</span>{/if}
                              </td>
                              <td class="mono small">{h.version}</td>
                              <td class="mono small">{#if h.candidate}<span class="dot {h.security ? 'bad' : h.security === null ? 'warn' : 'muted'}" aria-hidden="true"></span> {h.candidate}{:else}<span class="nil" aria-label="up to date"></span>{/if}</td>
                              <td>{#if h.vulns}<VulnBadge critical={h.critical} high={h.high} total={h.vulns} />{:else}<span class="nil" aria-label="none known"></span>{/if}</td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                    </div>
                    {#if groups.length}
                      <div class="upgrade">
                        {#if canWrite()}
                          <button class="btn small primary" disabled={upgrading === r.name} onclick={() => upgradeAll(r.name, list)}>
                            {upgrading === r.name ? 'Queuing…' : `Upgrade on ${groups.reduce((n, g) => n + g.hosts.length, 0)} host${groups.reduce((n, g) => n + g.hosts.length, 0) === 1 ? '' : 's'}`}
                          </button>
                        {/if}
                        <details class="by-hand">
                          <summary>Or upgrade by hand</summary>
                          <FixCommands {groups} tab="software" />
                        </details>
                      </div>
                    {/if}
                  {/if}
                </td>
              </tr>
            {/if}
          {/each}
        </tbody>
      </table>
    </div>
    {#if visible.length < filtered.length}
      <div class="more"><button class="btn ghost small" onclick={() => (limit = Infinity)}>Show all {filtered.length}</button></div>
    {/if}
  {/if}
</div>

<style>
  .summary-card { margin-bottom: var(--space-md); }
  .strip { display: flex; flex-wrap: wrap; }
  .strip > div { flex: 1 1 128px; }
  @media (max-width: 640px) { .strip > div { flex: 1 1 50%; min-width: 0; } }
  .filterbar .check { display: inline-flex; min-height: var(--control); }
  .linkish { padding: 0; border: 0; background: none; color: var(--link, var(--color-accent-deep)); cursor: pointer; text-align: left; font-size: inherit; }
  .linkish:hover { text-decoration: underline; }
  .versions, .cves { display: inline-flex; flex-wrap: wrap; align-items: center; gap: var(--space-2xs); }
  .detail > td { background: var(--color-paper); padding: var(--space-sm) var(--space-md) var(--space-md); }
  .inner { margin-bottom: var(--space-sm); }
  .upgrade { display: flex; flex-direction: column; align-items: flex-start; gap: var(--space-sm); }
  .by-hand { width: 100%; }
  .by-hand > summary { width: fit-content; cursor: pointer; font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--color-ink-2); }
  .by-hand[open] > summary { margin-bottom: var(--space-xs); }
  .small-skel { height: 80px; }
  .bad-text { color: var(--bad); font-weight: 600; }
</style>
