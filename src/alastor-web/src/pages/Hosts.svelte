<script lang="ts">
  import { fleet, refreshFleet } from '../lib/fleet.svelte';
  import { refreshOn } from '../lib/live.svelte';
  import { route } from '../lib/router.svelte';
  import { canWrite } from '../lib/session.svelte';
  import { scoreTone } from '../lib/baseline';
  import { api, errorText, type HostSummary } from '../lib/api';
  import { toast } from '../lib/toast.svelte';
  import { confirm } from '../lib/ui/confirm.svelte';
  import { liveUptime, uptime } from '../lib/format';
  import { rebootHost } from '../lib/hostActions';
  import Meter from '../lib/ui/Meter.svelte';
  import UpdatesBadge from '../lib/ui/UpdatesBadge.svelte';
  import VulnBadge from '../lib/ui/VulnBadge.svelte';
  import { indexTone } from '../lib/hardening';
  import { exposureLook } from '../lib/network';
  import { clock } from '../lib/ui/clock.svelte';
  import Time from '../lib/ui/Time.svelte';

  type Filter = '' | 'online' | 'offline' | 'problems' | 'pending' | 'baseline' | 'updates' | 'reboot' | 'cves';
  type View = 'table' | 'grid';

  const params = new URLSearchParams(route.search);
  let q = $state(params.get('q') ?? '');
  let filter = $state<Filter>((params.get('filter') as Filter) ?? '');
  let group = $state(params.get('group') ?? '');

  // The view is in the URL so a shared link opens the same layout; the last choice is remembered for plain /hosts.
  const viewKey = 'alastor.hostsView';
  function savedView(): View {
    try { return localStorage.getItem(viewKey) === 'grid' ? 'grid' : 'table'; } catch { return 'table'; }
  }
  const urlView = params.get('view');
  let view = $state<View>(urlView === 'grid' || urlView === 'table' ? urlView : savedView());

  $effect(() => {
    refreshFleet();
    return refreshOn(['hostUpdated'], refreshFleet, 30_000);
  });

  $effect(() => {
    const p = new URLSearchParams();
    if (q.trim()) p.set('q', q.trim());
    if (filter) p.set('filter', filter);
    if (group) p.set('group', group);
    if (view === 'grid') p.set('view', 'grid');
    try { localStorage.setItem(viewKey, view); } catch { /* storage blocked: the URL still carries it */ }
    const qs = p.toString();
    history.replaceState(null, '', qs ? `/hosts?${qs}` : '/hosts');
  });

  const shown = $derived(
    fleet.hosts.filter((h) => {
      const needle = q.trim().toLowerCase();
      if (needle && ![h.name, h.hostname, h.osPrettyName, h.groupName ?? '', ...h.tags].some((s) => s.toLowerCase().includes(needle))) return false;
      if (group === 'none' ? h.groupId !== null : group && h.groupId !== group) return false;
      switch (filter) {
        case 'online': return h.isOnline;
        case 'offline': return !h.isOnline;
        case 'problems': return h.toolsWithProblems > 0;
        case 'pending': return h.policySync !== 'in-sync';
        case 'baseline': return h.baselineFailing > 0;
        case 'updates': return (h.securityUpdates ?? h.pendingUpdates ?? 0) > 0;
        case 'reboot': return h.rebootRequired;
        case 'cves': return (h.vulnCritical ?? 0) + (h.vulnHigh ?? 0) > 0;
        default: return true;
      }
    }),
  );

  async function installShown() {
    const ids = shown.map((h) => h.id);
    const ok = await confirm(`Install security updates on ${ids.length} host${ids.length === 1 ? '' : 's'}?`,
      'Each agent installs its pending security updates with its own package manager (on Alpine: all pending updates). Services may restart; hosts are never rebooted.',
      { confirmLabel: 'Install now' });
    if (!ok) return;
    try {
      await api('/api/updates/apply', { method: 'POST', body: JSON.stringify({ hostIds: ids }) });
      toast(`Queued on ${ids.length} host${ids.length === 1 ? '' : 's'}. Offline hosts install when they reconnect.`);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }
</script>

<div class="page-head">
  <div>
    <h1>Hosts</h1>
    <p class="sub">{fleet.hosts.length} enrolled, {fleet.hosts.filter((h) => h.isOnline).length} online</p>
  </div>
  {#if canWrite()}
    <div class="actions"><a class="btn primary" href="/settings/enrollment">+ Add host</a></div>
  {/if}
</div>

<div class="filterbar">
  <input class="field grow" type="search" placeholder="Search name, OS, group, tag…" bind:value={q} aria-label="Search hosts" />
  <select class="field" bind:value={filter} aria-label="Status">
    <option value="">Any status</option>
    <option value="online">Online</option>
    <option value="offline">Offline</option>
    <option value="problems">Tool problems</option>
    <option value="pending">Policy not applied</option>
    <option value="baseline">Failing baseline checks</option>
    <option value="updates">Security updates pending</option>
    <option value="reboot">Reboot required</option>
    <option value="cves">Critical or high CVEs</option>
  </select>
  {#if filter === 'updates' && shown.length && canWrite()}
    <button class="btn primary" onclick={installShown}>Install on {shown.length} host{shown.length === 1 ? '' : 's'}</button>
  {/if}
  <select class="field" bind:value={group} aria-label="Group">
    <option value="">All groups</option>
    <option value="none">No group</option>
    {#each fleet.groups as g (g.id)}<option value={g.id}>{g.name}</option>{/each}
  </select>
  <div class="seg" role="group" aria-label="Layout">
    {#each [['table', 'Table'], ['grid', 'Grid']] as [v, label] (v)}
      <button class:on={view === v} aria-pressed={view === v} onclick={() => (view = v as View)}>{label}</button>
    {/each}
  </div>
</div>

{#if fleet.error}<div class="banner bad" role="alert"><p>{fleet.error}</p></div>{/if}

<!-- Cells shared by the table and the cards. -->
{#snippet nil()}<span class="nil" aria-label="none"></span>{/snippet}

{#snippet tagList(h: HostSummary)}
  <div class="tagcell">
    {#if h.groupName}<span class="pill tag group">{h.groupName}</span>{/if}
    {#each h.tags as t (t)}<span class="pill tag">{t}</span>{/each}
    {#if !h.groupName && !h.tags.length}{@render nil()}{/if}
  </div>
{/snippet}

{#snippet bans(h: HostSummary)}
  {#if h.activeBans}<a href="/bans?host={h.id}">{h.activeBans}</a>{:else}<span class="muted">0</span>{/if}
{/snippet}

{#snippet tools(h: HostSummary)}
  {#if h.toolsWithProblems > 0}<span class="pill warn">{h.toolsWithProblems} problem{h.toolsWithProblems > 1 ? 's' : ''}</span>
  {:else}<span class="pill ok">{h.toolsRunning} running</span>{/if}
{/snippet}

{#snippet policy(h: HostSummary)}
  {#if h.policySync === 'in-sync'}<span class="pill ok">in sync</span>
  {:else if h.policySync === 'failed'}<span class="pill bad">failed</span>
  {:else}<span class="pill info">pending</span>{/if}
{/snippet}

{#snippet baseline(h: HostSummary)}
  {#if h.baselineScore !== null}<a href="/hosts/{h.id}?tab=baseline" title="{h.baselineFailing} failing check{h.baselineFailing === 1 ? '' : 's'}"><span class="pill {scoreTone(h.baselineScore)}">{h.baselineScore}</span></a>
  {:else}{@render nil()}{/if}
{/snippet}

{#snippet lynis(h: HostSummary)}
  {#if h.hardeningIndex !== null}<a href="/hosts/{h.id}?tab=hardening" title="{h.hardeningWarnings ?? 0} warning{h.hardeningWarnings === 1 ? '' : 's'}"><span class="pill {indexTone(h.hardeningIndex)}">{h.hardeningIndex}</span></a>
  {:else}{@render nil()}{/if}
{/snippet}

{#snippet ssh(h: HostSummary)}
  {#if h.sshExposure !== null}<a href="/hosts/{h.id}?tab=network"><span class="pill {exposureLook(h.sshExposure, h.sshExposureAccepted).tone}">{exposureLook(h.sshExposure, h.sshExposureAccepted).label}</span></a>
  {:else}{@render nil()}{/if}
{/snippet}

{#snippet updates(h: HostSummary, withReboot: boolean)}
  {#if h.pendingUpdates !== null}<a href="/hosts/{h.id}?tab=updates"><UpdatesBadge pending={h.pendingUpdates} security={h.securityUpdates} /></a>
    {#if withReboot && h.rebootRequired}<span class="pill warn" title="Reboot required">reboot</span>{/if}
  {:else}{@render nil()}{/if}
{/snippet}

{#snippet cves(h: HostSummary)}
  {#if h.vulnTotal !== null}<a href="/hosts/{h.id}?tab=vulnerabilities"><VulnBadge critical={h.vulnCritical} high={h.vulnHigh} total={h.vulnTotal} /></a>
  {:else}{@render nil()}{/if}
{/snippet}

{#if !fleet.loaded || shown.length === 0}
  <div class="card">
    {#if !fleet.loaded}
      <div class="skeleton-block"></div>
    {:else}
      <div class="empty">
        {#if fleet.hosts.length === 0}
          No hosts enrolled yet. {#if canWrite()}<a href="/settings/enrollment">Create an enrollment token</a> to add one.{/if}
        {:else}
          No hosts match these filters.
        {/if}
      </div>
    {/if}
  </div>
{:else if view === 'grid'}
  <div class="host-grid">
    {#each shown as h (h.id)}
      {@const up = liveUptime(h, clock.now)}
      <article class="card hostcard">
        <header>
          <div class="host">
            <span class="dot" class:ok={h.isOnline} class:bad={!h.isOnline} title={h.isOnline ? 'Online' : 'Offline'}></span>
            <div class="title">
              <a href="/hosts/{h.id}" class="name">{h.name}</a>
              <div class="sysline muted small"><span>{h.osPrettyName}</span><span>{h.architecture}</span></div>
            </div>
          </div>
          <div class="flags">
            {#if !h.isOnline}<span class="pill bad">offline</span>{/if}
            {#if h.malwareFindings}<a href="/hosts/{h.id}?tab=malware" class="pill bad" title="Infected files found by ClamAV">malware: {h.malwareFindings}</a>{/if}
            {#if h.rebootRequired}<a href="/hosts/{h.id}?tab=updates" class="pill warn" title="Installed updates are waiting for a reboot">reboot required</a>{/if}
          </div>
        </header>

        <div class="meters">
          <div><span class="label">CPU</span><Meter value={h.cpuPercent} /></div>
          <div><span class="label">Memory</span><Meter value={h.memoryPercent} /></div>
          <div><span class="label">Disk</span><Meter value={h.diskPercent} warn={85} /></div>
        </div>

        <dl class="kv meta">
          <dt>Uptime</dt>
          <dd>{#if up !== null}{uptime(up)}{:else if !h.isOnline}<span class="muted">down, last seen <Time iso={h.lastSeenAt} /></span>{:else}{@render nil()}{/if}</dd>
          <dt>Load</dt><dd class="mono">{h.load1.toFixed(2)}</dd>
          <dt>Kernel</dt><dd class="mono">{#if h.kernelVersion}{h.kernelVersion}{:else}{@render nil()}{/if}</dd>
          <dt>IP</dt>
          <dd class="mono" title={h.ipAddresses.join(', ')}>
            {#if h.ipAddresses.length}{h.ipAddresses.slice(0, 2).join(', ')}{#if h.ipAddresses.length > 2}<span class="muted"> +{h.ipAddresses.length - 2}</span>{/if}
            {:else}{@render nil()}{/if}
          </dd>
          <dt>Agent</dt><dd class="mono">{h.agentVersion}</dd>
          <dt>Last seen</dt><dd><Time iso={h.lastSeenAt} /></dd>
          <dt>Group, tags</dt><dd>{@render tagList(h)}</dd>
        </dl>

        <dl class="posture">
          <div><dt title="Security baseline score">Baseline</dt><dd>{@render baseline(h)}</dd></div>
          <div><dt title="Lynis hardening index">Lynis</dt><dd>{@render lynis(h)}</dd></div>
          <div><dt title="Is SSH reachable from the internet?">SSH</dt><dd>{@render ssh(h)}</dd></div>
          <div><dt title="Pending package updates">Updates</dt><dd>{@render updates(h, false)}</dd></div>
          <div><dt title="Open vulnerabilities in installed packages">CVEs</dt><dd>{@render cves(h)}</dd></div>
          <div><dt title="Active IP bans on this host">Bans</dt><dd>{@render bans(h)}</dd></div>
          <div><dt title="Security tools the agent manages here, and any with problems">Tools</dt><dd>{@render tools(h)}</dd></div>
          <div><dt title="Has the agent applied the latest policy?">Policy</dt><dd>{@render policy(h)}</dd></div>
        </dl>

        <footer>
          <a class="btn small" href="/hosts/{h.id}">Details</a>
          {#if canWrite()}
            <button class="btn small danger" disabled={!h.isOnline} title={h.isOnline ? 'Reboot this host in one minute' : 'The host is offline'} onclick={() => rebootHost(h)}>Reboot</button>
          {/if}
        </footer>
      </article>
    {/each}
  </div>
{:else}
  <div class="card table-wrap hosts-table">
    <table class="table">
      <thead>
        <tr>
          <th>Host</th>
          <th class="hide-sm">Group, tags</th>
          <th>CPU</th>
          <th class="hide-sm">Memory</th>
          <th class="hide-sm">Disk</th>
          <th class="num" title="Active IP bans on this host">Bans</th>
          <th title="Security tools the agent manages here, and any with problems">Tools</th>
          <th title="Has the agent applied the latest policy?">Policy</th>
          <th class="num hide-sm" title="Security baseline score">Baseline</th>
          <th class="num hide-sm" title="Lynis hardening index">Lynis</th>
          <th class="hide-sm" title="Is SSH reachable from the internet?">SSH</th>
          <th class="hide-sm" title="Pending package updates and whether a reboot is needed">Updates</th>
          <th class="hide-sm" title="Open vulnerabilities in installed packages">CVEs</th>
          <th class="hide-sm" title="Time since the host last booted">Uptime</th>
          <th class="hide-sm">Last seen</th>
        </tr>
      </thead>
      <tbody>
        {#each shown as h (h.id)}
          {@const up = liveUptime(h, clock.now)}
          <tr>
            <td>
              <div class="host">
                <span class="dot" class:ok={h.isOnline} class:bad={!h.isOnline} title={h.isOnline ? 'Online' : 'Offline'}></span>
                <div>
                  <a href="/hosts/{h.id}" class="name">{h.name}</a>
                  {#if h.malwareFindings}<a href="/hosts/{h.id}?tab=malware" class="pill bad" title="Infected files found by ClamAV">malware: {h.malwareFindings}</a>{/if}
                  <div class="sysline muted small"><span>{h.osPrettyName}</span><span>{h.architecture}</span>{#if !h.isOnline}<span>offline</span>{/if}</div>
                </div>
              </div>
            </td>
            <td class="hide-sm">{@render tagList(h)}</td>
            <td><Meter value={h.cpuPercent} /></td>
            <td class="hide-sm"><Meter value={h.memoryPercent} /></td>
            <td class="hide-sm"><Meter value={h.diskPercent} warn={85} /></td>
            <td class="num">{@render bans(h)}</td>
            <td>{@render tools(h)}</td>
            <td>{@render policy(h)}</td>
            <td class="num hide-sm">{@render baseline(h)}</td>
            <td class="num hide-sm">{@render lynis(h)}</td>
            <td class="hide-sm nowrap">{@render ssh(h)}</td>
            <td class="hide-sm nowrap">{@render updates(h, true)}</td>
            <td class="hide-sm nowrap">{@render cves(h)}</td>
            <td class="hide-sm nowrap">{#if up !== null}{uptime(up)}{:else}{@render nil()}{/if}</td>
            <td class="hide-sm nowrap"><Time iso={h.lastSeenAt} /></td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

<style>
  .host { display: flex; align-items: flex-start; gap: var(--space-sm); min-width: 200px; }
  .host .dot { margin-top: var(--space-xs); }
  .name { white-space: nowrap; font-family: var(--font-display); font-weight: 600; font-size: var(--text-lg); color: var(--text-strong); margin-right: var(--space-2xs); }
  .sysline { display: flex; flex-wrap: wrap; }
  .sysline span + span { margin-left: var(--space-xs); padding-left: var(--space-xs); box-shadow: inset 1px 0 0 var(--border-strong); }
  .sysline { flex-wrap: nowrap; white-space: nowrap; }
  .tagcell { display: flex; flex-wrap: wrap; gap: var(--space-2xs); max-width: 200px; }
  td :global(.pill) + :global(.pill) { margin-left: 0; }
  .filterbar .seg { align-self: center; }

  .host-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 320px), 1fr)); gap: var(--space-md); }
  .hostcard { display: flex; flex-direction: column; min-width: 0; }
  .hostcard > header { align-items: flex-start; padding-block: var(--space-sm); }
  .hostcard .host { min-width: 0; }
  .hostcard .title { min-width: 0; }
  .hostcard .name { display: block; overflow: hidden; text-overflow: ellipsis; }
  .hostcard .sysline { flex-wrap: wrap; white-space: normal; }
  .flags { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: var(--space-2xs); }
  .meters { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--space-sm); padding: var(--space-sm) var(--space-md); border-bottom: var(--rule-hair) solid var(--border); }
  .meters > div, .posture > div { display: flex; flex-direction: column; gap: var(--space-2xs); min-width: 0; }
  .label, .posture dt { font-family: var(--font-display); font-weight: 500; font-size: var(--text-xs); color: var(--muted); }
  .meta { padding: var(--space-sm) var(--space-md); font-size: var(--text-sm); }
  .meta .tagcell { max-width: none; }
  .posture { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: var(--space-sm) var(--space-xs); margin: 0; padding: var(--space-sm) var(--space-md); border-top: var(--rule-hair) solid var(--border); background: var(--color-paper); }
  .posture dd { margin: 0; display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2xs); }
  .hostcard > footer { display: flex; justify-content: flex-end; gap: var(--space-xs); margin-top: auto; padding: var(--space-sm) var(--space-md); border-top: var(--rule-hair) solid var(--border); }
  @media (max-width: 400px) { .posture { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
</style>
