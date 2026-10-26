<script lang="ts">
  import { untrack } from 'svelte';
  import { api, errorText, vulnUrl, type Command, type HostSoftware, type SoftwarePackage } from './api';
  import { on, refreshOn } from './live.svelte';
  import PackageActionDialog from './PackageActionDialog.svelte';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import Icon from './ui/Icon.svelte';
  import Severity from './ui/Severity.svelte';
  import Time from './ui/Time.svelte';
  import VulnBadge from './ui/VulnBadge.svelte';

  let { hostId, hostName, isOnline }: { hostId: string; hostName: string; isOnline: boolean } = $props();

  let data = $state<HostSoftware | null>(null);
  let error = $state('');
  let refreshing = $state(false);
  let q = $state('');
  let scope = $state<'manual' | 'all'>('manual');
  let onlyUpdates = $state(false);
  let onlyVulns = $state(false);
  let limit = $state(100);
  let expanded = $state<string | null>(null);
  // Packages with an upgrade or uninstall queued, until a newer action result arrives.
  let pending = $state<Record<string, 'upgrade' | 'remove'>>({});
  let dialog = $state<{ open: boolean; pkg: SoftwarePackage | null; op: 'upgrade' | 'remove' }>({ open: false, pkg: null, op: 'upgrade' });

  async function load() {
    try {
      const prevCollected = data?.collectedAt;
      const prevAction = data?.lastAction?.atUtc;
      data = await api<HostSoftware>(`/api/hosts/${hostId}/software`);
      error = '';
      if (refreshing && data.collectedAt !== prevCollected) refreshing = false;
      if (data.lastAction && data.lastAction.atUtc !== prevAction) {
        const { [data.lastAction.package]: _, ...rest } = pending;
        pending = rest;
      }
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    void hostId;
    untrack(load);
    const offs = [
      on('hostUpdated', (h: { id: string }) => { if (h.id === hostId) load(); }),
      refreshOn(['policyChanged'], load, 60_000),
    ];
    return () => offs.forEach((o) => o());
  });

  const attention = (p: SoftwarePackage) => p.vulns.length > 0 || p.candidate !== null;
  // Exploited first, then by worst severity, then outdated (security first), then by name.
  const rank = (p: SoftwarePackage) => (p.exploited ? 1e6 : 0) + p.critical * 1e4 + p.high * 1e2 + p.vulns.length + (p.candidate ? (p.security ? 0.6 : 0.3) : 0);
  const sorted = $derived([...(data?.packages ?? [])].sort((a, b) => rank(b) - rank(a) || a.name.localeCompare(b.name)));
  const filtered = $derived.by(() => {
    const needle = q.trim().toLowerCase();
    return sorted.filter((p) =>
      (scope === 'all' || p.manual || needle !== '') &&
      (!onlyUpdates || p.candidate !== null) &&
      (!onlyVulns || p.vulns.length > 0) &&
      (!needle || p.name.toLowerCase().includes(needle) || (p.source ?? '').toLowerCase().includes(needle)));
  });
  const visible = $derived(filtered.slice(0, limit));
  const withUpdates = $derived(sorted.filter((p) => p.candidate !== null));
  const withSecurity = $derived(withUpdates.filter((p) => p.security === true));
  const withVulns = $derived(sorted.filter((p) => p.vulns.length > 0));
  const hiddenAttention = $derived(scope === 'manual' && !q.trim() ? sorted.filter((p) => !p.manual && attention(p)).length : 0);
  const schedule = $derived(data?.schedules.find((s) => s.key === 'updates.inventorySchedule'));

  async function refresh() {
    try {
      await api<Command>(`/api/hosts/${hostId}/actions/collect-software`, { method: 'POST' });
      refreshing = true;
      toast(isOnline ? 'Inventory requested. It takes a few seconds.' : 'The host is offline; it collects the inventory when the agent reconnects.');
      setTimeout(() => (refreshing = false), 5 * 60_000);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  function openAction(pkg: SoftwarePackage, op: 'upgrade' | 'remove') {
    dialog = { open: true, pkg, op };
  }

  function queued(op: 'upgrade' | 'remove', name: string) {
    pending = { ...pending, [name]: op };
    setTimeout(() => { const { [name]: _, ...rest } = pending; pending = rest; }, 15 * 60_000);
  }

  const osvNote = $derived.by(() => {
    if (!data) return '';
    if (!data.osvEnabled) return 'OSV.dev lookups are turned off on this server';
    if (!data.osvEcosystem) return 'OSV.dev doesn\'t cover this distribution';
    return data.osvCheckedAt ? `OSV.dev (${data.osvEcosystem})` : `OSV.dev (${data.osvEcosystem}) lookup pending`;
  });
</script>

{#if error && !data}
  <div class="banner bad" role="alert"><p>Couldn't load the software inventory: {error}</p></div>
{:else if !data}
  <div class="skeleton-block"></div>
{:else}
  <div class="stack">
    <section class="card summary">
      <div class="lead">
        <span class="figure-label">Installed on purpose</span>
        <span class="figure-value">{#if data.collectedAt}{data.manual}{:else}<span class="nil" aria-label="none"></span>{/if}</span>
      </div>
      <div class="counts">
        {#if data.collectedAt}
          <span class="pair"><strong class="n">{data.total}</strong> packages in total</span>
          <span class="pair" title="Packages with a newer version in the host's repositories, from the last update check"><strong class="n">{withUpdates.length}</strong> with updates{#if withSecurity.length}<span class="pill bad">{withSecurity.length} security</span>{/if}</span>
          <span class="pair" title="Packages with known vulnerabilities, from the host's CVE scan and OSV.dev"><strong class="n">{withVulns.length}</strong> with known CVEs</span>
          {#if data.manager}<span class="pair">via <code>{data.manager}</code></span>{/if}
        {/if}
      </div>
      <div class="meta">
        <span class="meta-facts">
          {#if data.collectedAt}<span>Collected <Time iso={data.collectedAt} /></span>{:else}<span>Not collected yet</span>{/if}
          <span title="Where known vulnerabilities come from, besides the host's own Trivy/Grype scan">{osvNote}</span>
        </span>
        <span class="keys">
          {#if canWrite()}<button class="btn small" onclick={refresh} disabled={refreshing}>{refreshing ? 'Collecting…' : 'Refresh inventory'}</button>{/if}
        </span>
      </div>
    </section>

    {#if data.success === false}
      <div class="banner bad" role="alert">
        <Icon name="error" />
        <p><strong>The last inventory failed:</strong> <span class="mono small">{data.error}</span>{data.collectedAt ? ' The list below is from the last successful one.' : ''}</p>
      </div>
    {/if}

    {#if data.lastAction}
      {@const a = data.lastAction}
      <section class="card">
        <header>
          <h2>Last {a.op === 'upgrade' ? 'upgrade' : 'uninstall'}</h2>
          <span class="hint"><Time iso={a.atUtc} /></span>
        </header>
        <div class="pad stack-sm">
          {#if a.success}
            <p>
              <span class="pill ok">succeeded</span>
              {#if a.op === 'upgrade'}
                {#if a.from === a.to}<span class="mono">{a.package}</span> was already the newest version (<span class="mono">{a.to}</span>).
                {:else}Upgraded <span class="mono">{a.package}</span> from <span class="mono">{a.from}</span> to <span class="mono">{a.to}</span>.{/if}
              {:else}Uninstalled <span class="mono">{a.package}</span> <span class="mono muted">{a.from}</span>.{/if}
            </p>
          {:else}
            <p><span class="pill bad">failed</span> {a.op === 'upgrade' ? 'Upgrading' : 'Uninstalling'} <span class="mono">{a.package}</span>: <span class="mono small">{a.error}</span></p>
          {/if}
          {#if a.logTail}
            <details class="output">
              <summary>Package manager output</summary>
              <pre class="code-block log">{a.logTail}</pre>
            </details>
          {/if}
        </div>
      </section>
    {/if}

    {#if !data.collectedAt}
      <div class="empty empty-dashed">
        This host hasn't reported its installed software yet. Agents collect it on startup and then on <code>updates.inventorySchedule</code> ({schedule?.value ?? 'every 6h'}).
        If the agent is older than this server, update it first.
      </div>
    {:else}
      <div class="filterbar">
        <input class="field grow" type="search" placeholder="Package or source name…" bind:value={q} aria-label="Search packages" />
        <div class="seg" role="group" aria-label="Which packages">
          <button class:on={scope === 'manual'} onclick={() => (scope = 'manual')} title="Packages an admin installed, not ones pulled in as dependencies">Installed on purpose</button>
          <button class:on={scope === 'all'} onclick={() => (scope = 'all')}>All {data.total}</button>
        </div>
        <label class="check"><input type="checkbox" bind:checked={onlyUpdates} /> Has update</label>
        <label class="check"><input type="checkbox" bind:checked={onlyVulns} /> Has CVEs</label>
      </div>

      {#if hiddenAttention}
        <p class="small muted hint-line">
          {hiddenAttention} package{hiddenAttention === 1 ? '' : 's'} installed as dependencies {hiddenAttention === 1 ? 'has' : 'have'} updates or known CVEs.
          <button class="btn ghost small" onclick={() => (scope = 'all')}>Show all packages</button>
        </p>
      {/if}

      <section class="card">
        {#if filtered.length === 0}
          <div class="empty">No package matches these filters.</div>
        {:else}
          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>Package</th>
                  <th class="hide-sm">Installed</th>
                  <th title="The newest version in the host's repositories, from the last update check. Red: a security update.">Available</th>
                  <th title="Known vulnerabilities in the installed version, from the host's CVE scan and OSV.dev">CVEs</th>
                  {#if canWrite()}<th class="actions" aria-label="Actions"></th>{/if}
                </tr>
              </thead>
              <tbody>
                {#each visible as p (p.name)}
                  <tr>
                    <td>
                      <span class="pkg">
                        <span class="mono" title={p.source && p.source !== p.name ? `Built from source package ${p.source}` : undefined}>{p.name}</span>
                        {#if !p.manual}<span class="pill tag" title="Pulled in as a dependency of another package">dependency</span>{/if}
                        {#if p.protected}<span class="pill tag" title="Essential to the system (boot, login, SSH or the package manager): never uninstalled from the dashboard">protected</span>{/if}
                      </span>
                      <div class="mono small muted show-sm">{p.version}</div>
                    </td>
                    <td class="mono small muted hide-sm">{p.version}</td>
                    <td class="mono small">
                      {#if p.candidate}<span class="avail"><span class="dot {p.security ? 'bad' : p.security === null ? 'warn' : 'muted'}" aria-hidden="true"></span>{p.candidate}</span>
                      {:else}<span class="nil" aria-label="up to date"></span>{/if}
                    </td>
                    <td>
                      {#if p.vulns.length}
                        <button class="linkish" onclick={() => (expanded = expanded === p.name ? null : p.name)} aria-expanded={expanded === p.name}>
                          <VulnBadge critical={p.critical} high={p.high} total={p.vulns.length} />
                          {#if p.exploited}<span class="pill bad" title="In CISA's Known Exploited Vulnerabilities catalog">exploited</span>{/if}
                        </button>
                      {:else}<span class="nil" aria-label="none known"></span>{/if}
                    </td>
                    {#if canWrite()}
                      <td class="actions nowrap">
                        {#if pending[p.name]}
                          <span class="muted small">{pending[p.name] === 'upgrade' ? 'Upgrading…' : 'Uninstalling…'}</span>
                        {:else}
                          {#if p.candidate}<button class="btn small primary" onclick={() => openAction(p, 'upgrade')}>Upgrade</button>{/if}
                          {#if !p.protected}<button class="btn small ghost" onclick={() => openAction(p, 'remove')}>Uninstall</button>{/if}
                        {/if}
                      </td>
                    {/if}
                  </tr>
                  {#if expanded === p.name}
                    <tr class="detail">
                      <td colspan={canWrite() ? 5 : 4}>
                        <ul class="vulns">
                          {#each p.vulns.slice(0, 50) as v (v.id)}
                            <li>
                              <a class="mono" href={vulnUrl(v.id)} target="_blank" rel="noreferrer">{v.id}</a>
                              {#if v.severity}<Severity value={v.severity} />{:else}<span class="pill muted" title="OSV.dev has no rating for this advisory">unrated</span>{/if}
                              {#if v.exploited}<span class="pill bad">exploited</span>{/if}
                              {#if v.fixed}<span class="small">fixed in <span class="mono">{v.fixed}</span></span>{/if}
                              <span class="pill tag" title={v.source === 'scan' ? 'Found by the host\'s Trivy/Grype scan' : `From OSV.dev${v.advisory ? ` advisory ${v.advisory}` : ''}`}>{v.source === 'scan' ? 'scan' : 'OSV'}</span>
                              {#if v.title}<span class="muted small title">{v.title}</span>{/if}
                            </li>
                          {/each}
                        </ul>
                        {#if p.vulns.length > 50}<p class="muted small">and {p.vulns.length - 50} more; see the CVEs tab.</p>{/if}
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
      </section>
      <p class="small muted">
        Updates come from the last update check (Updates tab). CVEs combine the host's own scan with OSV.dev, matched by package name and version;
        distributions often backport fixes, so check the advisory when a version looks old but is marked fixed.
      </p>
    {/if}
  </div>

  <PackageActionDialog bind:open={dialog.open} {hostId} {hostName} {isOnline} pkg={dialog.pkg} op={dialog.op} onQueued={queued} />
{/if}

<style>
  /* The summary ledger, the same strip on every host tab: lead figure | counts | when + keys, parted by hairlines. */
  .summary { display: grid; grid-template-columns: minmax(200px, max-content) minmax(0, 1fr) minmax(0, max-content); overflow: hidden; }
  .summary > * { display: flex; flex-direction: column; justify-content: center; gap: var(--space-2xs); min-width: 0; padding: var(--space-md); }
  .summary > * + * { box-shadow: inset 1px 0 0 var(--border); }
  .lead .figure-value { display: inline-flex; align-items: baseline; }
  .lead .figure-value .nil { width: 24px; height: 2px; align-self: center; }
  .counts { flex-direction: row; flex-wrap: wrap; align-items: center; align-content: center; justify-content: flex-start; gap: var(--space-xs) var(--space-lg); color: var(--muted); }
  .pair { display: inline-flex; align-items: baseline; gap: var(--space-2xs); color: var(--muted); }
  .pair .n { font-family: var(--font-display); font-weight: 600; font-size: var(--text-lg); line-height: 1; color: var(--text-strong); font-variant-numeric: tabular-nums; }
  .pair code { font-size: var(--text-code); }
  .meta { align-items: flex-end; text-align: right; }
  .meta-facts { display: flex; flex-direction: column; align-items: inherit; gap: var(--space-3xs); font-size: var(--text-sm); color: var(--muted); }
  .keys { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: var(--space-xs); margin-top: var(--space-2xs); }
  .keys:empty { display: none; }
  @media (max-width: 760px) {
    .summary { grid-template-columns: minmax(0, 1fr); }
    .summary > * + * { box-shadow: inset 0 1px 0 var(--border); }
    .counts:empty { display: none; }
    .meta { align-items: flex-start; text-align: left; }
    .keys { justify-content: flex-start; }
  }

  .pad { padding: var(--space-md); }
  .stack-sm { display: flex; flex-direction: column; gap: var(--space-xs); }
  .stack-sm p { margin: 0; }
  .filterbar .check { display: inline-flex; min-height: var(--control); }
  .hint-line { display: flex; align-items: center; flex-wrap: wrap; gap: var(--space-xs); margin: 0; }
  .pkg { display: inline-flex; align-items: center; flex-wrap: wrap; gap: var(--space-xs); }
  .avail { display: inline-flex; align-items: center; gap: var(--space-xs); white-space: nowrap; }
  .linkish { display: inline-flex; align-items: center; gap: var(--space-2xs); padding: 0; border: 0; background: none; cursor: pointer; }
  .actions { text-align: right; }
  .actions .btn + .btn { margin-left: var(--space-2xs); }
  .detail td { background: var(--color-paper); }
  .vulns { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: var(--space-2xs); }
  .vulns li { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-xs); }
  .vulns .title { flex-basis: 100%; display: -webkit-box; -webkit-line-clamp: 2; line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
  .show-sm { display: none; }
  @media (max-width: 640px) { .show-sm { display: block; } }
  .output > summary { width: fit-content; cursor: pointer; font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--color-ink-2); }
  .output > summary:hover { color: var(--text-strong); }
  .output[open] > summary { margin-bottom: var(--space-xs); }
  .log { max-height: 320px; }
  .more { padding: var(--space-sm); text-align: center; }
</style>
