<script lang="ts">
  import { fleet, refreshFleet } from '../lib/fleet.svelte';
  import { refreshOn } from '../lib/live.svelte';
  import { route } from '../lib/router.svelte';
  import { canWrite } from '../lib/session.svelte';
  import { scoreTone } from '../lib/baseline';
  import { api, errorText } from '../lib/api';
  import { toast } from '../lib/toast.svelte';
  import { confirm } from '../lib/ui/confirm.svelte';
  import Meter from '../lib/ui/Meter.svelte';
  import UpdatesBadge from '../lib/ui/UpdatesBadge.svelte';
  import VulnBadge from '../lib/ui/VulnBadge.svelte';
  import { indexTone } from '../lib/hardening';
  import Time from '../lib/ui/Time.svelte';

  type Filter = '' | 'online' | 'offline' | 'problems' | 'pending' | 'baseline' | 'updates' | 'reboot' | 'cves';

  const params = new URLSearchParams(route.search);
  let q = $state(params.get('q') ?? '');
  let filter = $state<Filter>((params.get('filter') as Filter) ?? '');
  let group = $state(params.get('group') ?? '');

  $effect(() => {
    refreshFleet();
    return refreshOn(['hostUpdated'], refreshFleet, 30_000);
  });

  $effect(() => {
    const p = new URLSearchParams();
    if (q.trim()) p.set('q', q.trim());
    if (filter) p.set('filter', filter);
    if (group) p.set('group', group);
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
    <p class="sub">{fleet.hosts.length} enrolled · {fleet.hosts.filter((h) => h.isOnline).length} online</p>
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
</div>

{#if fleet.error}<div class="banner bad" role="alert"><p>{fleet.error}</p></div>{/if}

<div class="card table-wrap">
  {#if !fleet.loaded}
    <div class="skeleton-block"></div>
  {:else if shown.length === 0}
    <div class="empty">
      {#if fleet.hosts.length === 0}
        No hosts enrolled yet. {#if canWrite()}<a href="/settings/enrollment">Create an enrollment token</a> to add one.{/if}
      {:else}
        No hosts match these filters.
      {/if}
    </div>
  {:else}
    <table class="table">
      <thead>
        <tr>
          <th>Host</th>
          <th class="hide-sm">Group · tags</th>
          <th>CPU</th>
          <th class="hide-sm">Memory</th>
          <th class="hide-sm">Disk</th>
          <th class="num">Bans</th>
          <th>Tools</th>
          <th>Policy</th>
          <th class="num hide-sm" title="Security baseline score">Baseline</th>
          <th class="num hide-sm" title="Lynis hardening index">Lynis</th>
          <th class="hide-sm">Updates</th>
          <th class="hide-sm">CVEs</th>
          <th class="hide-sm">Last seen</th>
        </tr>
      </thead>
      <tbody>
        {#each shown as h (h.id)}
          <tr>
            <td>
              <div class="host">
                <span class="dot" class:ok={h.isOnline} class:bad={!h.isOnline} title={h.isOnline ? 'Online' : 'Offline'}></span>
                <div>
                  <a href="/hosts/{h.id}" class="name">{h.name}</a>
                  <div class="muted small">{h.osPrettyName} · {h.architecture}{h.isOnline ? '' : ' · offline'}</div>
                </div>
              </div>
            </td>
            <td class="hide-sm">
              {#if h.groupName}<span class="pill info">{h.groupName}</span>{/if}
              {#each h.tags as t (t)}<span class="pill muted tag">{t}</span>{/each}
              {#if !h.groupName && !h.tags.length}<span class="muted">—</span>{/if}
            </td>
            <td><Meter value={h.cpuPercent} /></td>
            <td class="hide-sm"><Meter value={h.memoryPercent} /></td>
            <td class="hide-sm"><Meter value={h.diskPercent} warn={85} /></td>
            <td class="num">{#if h.activeBans}<a href="/bans?host={h.id}">{h.activeBans}</a>{:else}<span class="muted">0</span>{/if}</td>
            <td>
              {#if h.toolsWithProblems > 0}<span class="pill warn">⚠ {h.toolsWithProblems} problem{h.toolsWithProblems > 1 ? 's' : ''}</span>
              {:else}<span class="pill ok">✓ {h.toolsRunning} running</span>{/if}
            </td>
            <td>
              {#if h.policySync === 'in-sync'}<span class="pill ok">✓ in sync</span>
              {:else if h.policySync === 'failed'}<span class="pill bad">✕ failed</span>
              {:else}<span class="pill info">… pending</span>{/if}
            </td>
            <td class="num hide-sm">
              {#if h.baselineScore !== null}<a href="/hosts/{h.id}?tab=baseline" title="{h.baselineFailing} failing check{h.baselineFailing === 1 ? '' : 's'}"><span class="pill {scoreTone(h.baselineScore)}">{h.baselineScore}</span></a>
              {:else}<span class="muted">—</span>{/if}
            </td>
            <td class="num hide-sm">
              {#if h.hardeningIndex !== null}<a href="/hosts/{h.id}?tab=hardening" title="{h.hardeningWarnings ?? 0} warning{h.hardeningWarnings === 1 ? '' : 's'}"><span class="pill {indexTone(h.hardeningIndex)}">{h.hardeningIndex}</span></a>
              {:else}<span class="muted">—</span>{/if}
            </td>
            <td class="hide-sm nowrap">
              {#if h.pendingUpdates !== null}<a href="/hosts/{h.id}?tab=updates"><UpdatesBadge pending={h.pendingUpdates} security={h.securityUpdates} /></a>
                {#if h.rebootRequired}<span class="pill warn" title="Reboot required">↻</span>{/if}
              {:else}<span class="muted">—</span>{/if}
            </td>
            <td class="hide-sm nowrap">
              {#if h.vulnTotal !== null}<a href="/hosts/{h.id}?tab=vulnerabilities"><VulnBadge critical={h.vulnCritical} high={h.vulnHigh} total={h.vulnTotal} /></a>
              {:else}<span class="muted">—</span>{/if}
            </td>
            <td class="hide-sm nowrap"><Time iso={h.lastSeenAt} /></td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .host { display: flex; align-items: center; gap: 10px; }
  .name { font-weight: 600; }
  .tag { margin-left: 4px; }
</style>
