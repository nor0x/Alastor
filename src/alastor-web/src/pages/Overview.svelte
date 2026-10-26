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

{#if error}<div class="banner bad" role="alert"><p>Couldn’t load the overview: {error}</p></div>{/if}

{#if data}
  {#if data.hostsTotal === 0}
    <div class="card welcome">
      <div>
        <h2>Add your first server</h2>
        <p class="muted">Create an enrollment token, then run the install command on the server. It shows up here within a minute.</p>
      </div>
      <a class="btn primary" href="/settings/enrollment">Create enrollment token</a>
    </div>
  {/if}

  <section class="card ledger-panel" aria-label="Fleet summary">
    <div class="band">
      <h2 class="band-name">Fleet</h2>
      <div class="ledger">
        <a class="ledger-cell" href="/hosts">
          <span class="figure-label">Hosts online</span>
          <span class="figure-value">{data.hostsOnline}<span class="figure-of">/ {data.hostsTotal}</span></span>
          {#if data.hostsOffline > 0}<span class="figure-foot bad"><span class="dot bad"></span>{data.hostsOffline} offline</span>{:else}<span class="figure-foot">all reporting</span>{/if}
        </a>
        <a class="ledger-cell" href="/events?minSeverity=Medium">
          <span class="figure-label">Alerts · 24h</span>
          <span class="figure-value">{number.format(data.alerts24h)}</span>
          <span class="figure-foot">{number.format(data.events24h)} events total</span>
        </a>
        <a class="ledger-cell" href="/bans">
          <span class="figure-label">Active bans</span>
          <span class="figure-value">{number.format(data.activeBans)}</span>
          <span class="figure-foot">{number.format(data.bans24h)} new in 24h</span>
        </a>
        <a class="ledger-cell" href="/hosts?filter=problems">
          <span class="figure-label">Tool problems</span>
          <span class="figure-value" class:warn={data.hostsWithToolProblems > 0}>{data.hostsWithToolProblems}</span>
          <span class="figure-foot" class:warn={data.hostsWithToolProblems > 0}>
            {data.hostsWithToolProblems === 0 ? 'everything running' : 'hosts need attention'}
          </span>
        </a>
        <a class="ledger-cell" href="/hosts?filter=pending">
          <span class="figure-label">Policy not applied</span>
          <span class="figure-value">{data.hostsPolicyPending}</span>
          <span class="figure-foot">hosts pending or failed</span>
        </a>
      </div>
    </div>
    <div class="band">
      <h2 class="band-name">Posture</h2>
      <div class="ledger">
        <a class="ledger-cell" href="/baseline">
          <span class="figure-label">Security baseline</span>
          <span class="figure-value">{#if data.averageBaselineScore !== null}{data.averageBaselineScore}<span class="figure-of">/ 100</span>{:else}<span class="nil" aria-label="none"></span>{/if}</span>
          {#if data.averageBaselineScore === null}<span class="figure-foot">no host checked yet</span>
          {:else if data.hostsFailingBaselineHigh > 0}<span class="figure-foot warn">{data.hostsFailingBaselineHigh} host{data.hostsFailingBaselineHigh > 1 ? 's' : ''} failing high-severity checks</span>
          {:else}<span class="figure-foot">no high-severity failures</span>{/if}
        </a>
        <a class="ledger-cell" href="/baseline?view=lynis">
          <span class="figure-label">Hardening index</span>
          <span class="figure-value">{#if data.averageHardeningIndex !== null}{data.averageHardeningIndex.toFixed(0)}{:else}<span class="nil" aria-label="none"></span>{/if}</span>
          <span class="figure-foot">{data.averageHardeningIndex === null ? 'not audited yet' : 'Lynis average across hosts'}</span>
        </a>
        <a class="ledger-cell" href="/hosts?filter=updates">
          <span class="figure-label">Pending security updates</span>
          <span class="figure-value">{#if data.hostsWithPendingSecurityUpdates !== null}{data.hostsWithPendingSecurityUpdates}{:else}<span class="nil" aria-label="none"></span>{/if}</span>
          <span class="figure-foot">{data.hostsWithPendingSecurityUpdates === null ? 'not checked yet' : `host${data.hostsWithPendingSecurityUpdates === 1 ? '' : 's'} need updates`}</span>
        </a>
        <a class="ledger-cell" href="/vulnerabilities">
          <span class="figure-label">Critical &amp; high CVEs</span>
          <span class="figure-value">{#if data.hostsWithHighCves !== null}{data.hostsWithHighCves}{:else}<span class="nil" aria-label="none"></span>{/if}</span>
          <span class="figure-foot">{data.hostsWithHighCves === null ? 'not scanned yet' : `host${data.hostsWithHighCves === 1 ? '' : 's'} affected`}</span>
        </a>
        <a class="ledger-cell" href="/baseline?view=exposure">
          <span class="figure-label">Public SSH</span>
          <span class="figure-value">{#if data.hostsWithPublicSsh !== null}{data.hostsWithPublicSsh}{:else}<span class="nil" aria-label="none"></span>{/if}</span>
          <span class="figure-foot">{data.hostsWithPublicSsh === null ? 'not checked yet' : `host${data.hostsWithPublicSsh === 1 ? '' : 's'} reachable from the internet`}</span>
        </a>
        {#if data.hostsWithMalware !== null}
          <a class="ledger-cell" href="/hosts">
            <span class="figure-label">Malware</span>
            <span class="figure-value" class:bad={data.hostsWithMalware > 0}>{data.hostsWithMalware}</span>
            <span class="figure-foot">host{data.hostsWithMalware === 1 ? '' : 's'} with infected files (ClamAV)</span>
          </a>
        {/if}
      </div>
    </div>
  </section>

  <div class="columns">
    <section class="card">
      <header><h2>Recent alerts</h2><a class="hint" href="/events?minSeverity=Medium">All alerts</a></header>
      {#if data.recentAlerts.length}
        <EventList events={data.recentAlerts} hostNames={hostNames()} compact />
      {:else}
        <div class="empty">No medium-or-higher alerts in the last 24 hours.</div>
      {/if}
    </section>

    <div class="stack">
      <section class="card">
        <header><h2>Needs attention</h2><a class="hint" href="/hosts">All hosts</a></header>
        {#if attention.length}
          <ul class="hosts">
            {#each attention as h (h.id)}
              <li>
                <a class="host-name" href="/hosts/{h.id}">{h.name}</a>
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
          <div class="table-wrap">
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
          </div>
        {:else}
          <div class="empty">No offenders in the last 24 hours.</div>
        {/if}
      </section>

      {#if fleet.hosts.length}
        <section class="card">
          <header><h2>Busiest hosts</h2><span class="hint">by CPU</span></header>
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Host</th><th>CPU</th><th>Memory</th><th class="hide-sm">Disk</th></tr></thead>
              <tbody>
                {#each [...fleet.hosts].filter((h) => h.isOnline).sort((a, b) => b.cpuPercent - a.cpuPercent).slice(0, 5) as h (h.id)}
                  <tr>
                    <td><a class="host-name" href="/hosts/{h.id}">{h.name}</a></td>
                    <td><Meter value={h.cpuPercent} /></td>
                    <td><Meter value={h.memoryPercent} /></td>
                    <td class="hide-sm"><Meter value={h.diskPercent} warn={85} /></td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>
      {/if}
    </div>
  </div>
{:else if !error}
  <div class="skeleton-block ledger-skeleton"></div>
  <div class="columns"><div class="skeleton-block"></div><div class="skeleton-block"></div></div>
{/if}

<style>
  .welcome { display: flex; justify-content: space-between; align-items: center; gap: var(--space-md); flex-wrap: wrap; padding: var(--space-lg); margin-bottom: var(--space-md); }
  .welcome h2 { margin-bottom: var(--space-2xs); font-size: var(--text-xl); }
  .ledger-panel { margin-bottom: var(--space-lg); overflow: hidden; }
  .band { display: grid; grid-template-columns: 112px minmax(0, 1fr); }
  .band + .band { border-top: var(--rule-hair) solid var(--border-strong); }
  .band-name { padding: var(--space-md); font-size: var(--text-lg); box-shadow: 1px 0 0 var(--border); }
  .band .ledger { grid-template-columns: repeat(auto-fit, minmax(min(100%, 150px), 1fr)); }
  .band .ledger > * { padding: var(--space-md) var(--space-md) var(--space-sm); }
  .figure-foot { display: inline-flex; align-items: center; gap: var(--space-xs); }
  .figure-value .nil { width: 24px; height: 2px; }
  .columns { display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr); gap: var(--space-md); align-items: start; }
  .hosts { list-style: none; margin: 0; padding: 0; }
  .hosts li { display: flex; justify-content: space-between; align-items: center; gap: var(--space-xs); padding: var(--space-sm) var(--space-md); flex-wrap: wrap; }
  .hosts li + li { border-top: var(--rule-hair) solid var(--border); }
  .host-name { font-family: var(--font-display); font-weight: 500; white-space: nowrap; }
  .why { display: flex; gap: var(--space-2xs); flex-wrap: wrap; }
  .ledger-skeleton { height: 280px; margin-bottom: var(--space-lg); }
  @media (max-width: 1100px) { .columns { grid-template-columns: minmax(0, 1fr); } }
  @media (max-width: 760px) {
    .band { grid-template-columns: minmax(0, 1fr); }
    .band-name { box-shadow: 0 1px 0 var(--border); padding: var(--space-sm) var(--space-md); }
  }
</style>
