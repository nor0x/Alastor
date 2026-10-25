<script lang="ts">
  import { api, type Overview } from '../lib/api';
  import { refreshOn } from '../lib/live.svelte';
  import { fleet, hostNames } from '../lib/fleet.svelte';
  import { number } from '../lib/format';
  import EventList from '../lib/ui/EventList.svelte';
  import Time from '../lib/ui/Time.svelte';
  import Meter from '../lib/ui/Meter.svelte';

  let data = $state<Overview | null>(null);
  let error = $state('');

  async function load() {
    try {
      data = await api<Overview>('/api/overview');
      error = '';
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load';
    }
  }

  $effect(() => {
    load();
    return refreshOn(['hostUpdated', 'eventsCreated', 'bansChanged', 'policyChanged'], load);
  });

  // Hosts needing attention first: offline, tool problems, policy not applied.
  const attention = $derived(
    fleet.hosts
      .filter((h) => !h.isOnline || h.toolsWithProblems > 0 || h.policySync !== 'in-sync')
      .slice(0, 6),
  );
</script>

<div class="page-head">
  <div>
    <h1>Overview</h1>
    <p class="sub">Fleet health over the last 24 hours.</p>
  </div>
</div>

{#if error}<div class="banner bad" role="alert"><p>Couldn't load the overview: {error}</p></div>{/if}

{#if data}
  {#if data.hostsTotal === 0}
    <div class="card welcome">
      <h2>Add your first server</h2>
      <p class="muted">Create an enrollment token, then run the install command on the server. It shows up here within a minute.</p>
      <a class="btn primary" href="/settings/enrollment">Create enrollment token</a>
    </div>
  {/if}

  <section class="tiles" aria-label="Fleet summary">
    <a class="tile" href="/hosts">
      <span class="label">Hosts online</span>
      <span class="big">{data.hostsOnline}<span class="of">/ {data.hostsTotal}</span></span>
      {#if data.hostsOffline > 0}<span class="foot bad"><span class="dot bad"></span>{data.hostsOffline} offline</span>{:else}<span class="foot muted">all reporting</span>{/if}
    </a>
    <a class="tile" href="/events?minSeverity=Medium">
      <span class="label">Alerts · 24h</span>
      <span class="big">{number.format(data.alerts24h)}</span>
      <span class="foot muted">{number.format(data.events24h)} events total</span>
    </a>
    <a class="tile" href="/bans">
      <span class="label">Active bans</span>
      <span class="big">{number.format(data.activeBans)}</span>
      <span class="foot muted">{number.format(data.bans24h)} new in 24h</span>
    </a>
    <a class="tile" href="/hosts?filter=problems">
      <span class="label">Tool problems</span>
      <span class="big">{data.hostsWithToolProblems}</span>
      <span class="foot" class:warn={data.hostsWithToolProblems > 0} class:muted={data.hostsWithToolProblems === 0}>
        {data.hostsWithToolProblems === 0 ? 'everything running' : 'hosts need attention'}
      </span>
    </a>
    <a class="tile" href="/hosts?filter=pending">
      <span class="label">Policy not applied</span>
      <span class="big">{data.hostsPolicyPending}</span>
      <span class="foot muted">hosts pending or failed</span>
    </a>
    <a class="tile" href="/baseline">
      <span class="label">Security baseline</span>
      <span class="big">{data.averageBaselineScore ?? '—'}{#if data.averageBaselineScore !== null}<span class="of">/ 100</span>{/if}</span>
      {#if data.averageBaselineScore === null}<span class="foot muted">no host checked yet</span>
      {:else if data.hostsFailingBaselineHigh > 0}<span class="foot warn">{data.hostsFailingBaselineHigh} host{data.hostsFailingBaselineHigh > 1 ? 's' : ''} failing high-severity checks</span>
      {:else}<span class="foot muted">no high-severity failures</span>{/if}
    </a>
    <a class="tile" href="/hosts?filter=updates">
      <span class="label">Pending security updates</span>
      <span class="big">{data.hostsWithPendingSecurityUpdates ?? '—'}</span>
      <span class="foot muted">{data.hostsWithPendingSecurityUpdates === null ? 'not checked yet' : `host${data.hostsWithPendingSecurityUpdates === 1 ? '' : 's'} need updates`}</span>
    </a>
    <a class="tile" href="/vulnerabilities">
      <span class="label">Critical &amp; high CVEs</span>
      <span class="big">{data.hostsWithHighCves ?? '—'}</span>
      <span class="foot muted">{data.hostsWithHighCves === null ? 'not scanned yet' : `host${data.hostsWithHighCves === 1 ? '' : 's'} affected`}</span>
    </a>
    <a class="tile" href="/baseline?view=lynis">
      <span class="label">Hardening index</span>
      <span class="big">{data.averageHardeningIndex?.toFixed(0) ?? '—'}</span>
      <span class="foot muted">{data.averageHardeningIndex === null ? 'not audited yet' : 'Lynis average across hosts'}</span>
    </a>
  </section>

  <div class="grid-2">
    <section class="card">
      <header><h2>Recent alerts</h2><a class="hint" href="/events?minSeverity=Medium">All alerts →</a></header>
      {#if data.recentAlerts.length}
        <EventList events={data.recentAlerts} hostNames={hostNames()} compact />
      {:else}
        <div class="empty">No medium-or-higher alerts in the last 24 hours.</div>
      {/if}
    </section>

    <div class="stack">
      <section class="card">
        <header><h2>Needs attention</h2><a class="hint" href="/hosts">All hosts →</a></header>
        {#if attention.length}
          <ul class="hosts">
            {#each attention as h (h.id)}
              <li>
                <a href="/hosts/{h.id}">{h.name}</a>
                <span class="why">
                  {#if !h.isOnline}<span class="pill bad">offline · <Time iso={h.lastSeenAt} /></span>{/if}
                  {#if h.toolsWithProblems > 0}<span class="pill warn">{h.toolsWithProblems} tool problem{h.toolsWithProblems > 1 ? 's' : ''}</span>{/if}
                  {#if h.policySync === 'failed'}<span class="pill bad">policy failed</span>{:else if h.policySync === 'pending'}<span class="pill info">policy pending</span>{/if}
                </span>
              </li>
            {/each}
          </ul>
        {:else if fleet.hosts.length}
          <div class="empty">All hosts are online, in sync and healthy.</div>
        {:else}
          <div class="empty">No hosts yet.</div>
        {/if}
      </section>

      <section class="card">
        <header><h2>Top offenders · 24h</h2><span class="hint">ban and auth-failure events</span></header>
        {#if data.topOffenders.length}
          <table class="table">
            <thead><tr><th>IP</th><th class="num">Events</th><th class="num">Hosts</th></tr></thead>
            <tbody>
              {#each data.topOffenders as o (o.target)}
                <tr>
                  <td class="mono"><a href="/events?ip={encodeURIComponent(o.target)}">{o.target}</a></td>
                  <td class="num">{number.format(o.events)}</td>
                  <td class="num">{o.hosts}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {:else}
          <div class="empty">No offenders in the last 24 hours.</div>
        {/if}
      </section>

      {#if fleet.hosts.length}
        <section class="card">
          <header><h2>Busiest hosts</h2><span class="hint">by CPU</span></header>
          <table class="table">
            <thead><tr><th>Host</th><th>CPU</th><th>Memory</th><th class="hide-sm">Disk</th></tr></thead>
            <tbody>
              {#each [...fleet.hosts].filter((h) => h.isOnline).sort((a, b) => b.cpuPercent - a.cpuPercent).slice(0, 5) as h (h.id)}
                <tr>
                  <td><a href="/hosts/{h.id}">{h.name}</a></td>
                  <td><Meter value={h.cpuPercent} /></td>
                  <td><Meter value={h.memoryPercent} /></td>
                  <td class="hide-sm"><Meter value={h.diskPercent} warn={85} /></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </section>
      {/if}
    </div>
  </div>
{:else if !error}
  <div class="tiles">{#each Array(8) as _, i (i)}<div class="skeleton-block" style="height:96px"></div>{/each}</div>
{/if}

<style>
  .welcome { padding: 20px; margin-bottom: 16px; }
  .welcome h2 { margin: 0 0 4px; font-size: 16px; }
  .welcome p { margin: 0 0 14px; }
  .tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .tile {
    display: flex; flex-direction: column; gap: 2px; padding: 14px 16px;
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px; color: inherit;
  }
  a.tile:hover { border-color: var(--border-strong); text-decoration: none; background: var(--surface-2); }
  .label { color: var(--muted); font-size: 12px; }
  .big { font-size: 28px; font-weight: 600; color: var(--text-strong); font-variant-numeric: tabular-nums; line-height: 1.2; }
  .of { font-size: 16px; color: var(--muted); font-weight: 400; margin-left: 4px; }
  .foot { font-size: 12px; display: inline-flex; align-items: center; gap: 6px; }
  .foot.bad { color: var(--bad); }
  .foot.warn { color: var(--warn); }
  .hosts { list-style: none; margin: 0; padding: 4px 0; }
  .hosts li { display: flex; justify-content: space-between; align-items: center; gap: 8px; padding: 8px 16px; flex-wrap: wrap; }
  .why { display: flex; gap: 6px; flex-wrap: wrap; }
</style>
