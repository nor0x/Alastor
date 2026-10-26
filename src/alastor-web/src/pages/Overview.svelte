<script lang="ts">
  import { api, type EventStats, type IssueList as IssueListDto, type Overview, type PosturePoint, type PostureMatrix as Matrix } from '../lib/api';
  import { refreshOn } from '../lib/live.svelte';
  import { fleet, hostNames } from '../lib/fleet.svelte';
  import { number } from '../lib/format';
  import EventList from '../lib/ui/EventList.svelte';
  import Meter from '../lib/ui/Meter.svelte';
  import IssueList from '../lib/IssueList.svelte';
  import { refreshIssues } from '../lib/issues.svelte';
  import { counts, eventBuckets, trend } from '../lib/stats';
  import { severitySeries, utcOffsetMinutes } from '../lib/ui/chart';
  import BarList from '../lib/ui/BarList.svelte';
  import MetricChart from '../lib/ui/MetricChart.svelte';
  import PostureMatrix from '../lib/ui/PostureMatrix.svelte';
  import Sparkline from '../lib/ui/Sparkline.svelte';
  import StackedBars from '../lib/ui/StackedBars.svelte';

  let data = $state<Overview | null>(null);
  let openIssues = $state<IssueListDto | null>(null);
  let events = $state<EventStats | null>(null);
  let posture = $state<PosturePoint[]>([]);
  let matrix = $state<Matrix | null>(null);
  let trendDays = $state(30);
  let error = $state('');

  async function load() {
    try {
      data = await api<Overview>('/api/overview');
      error = '';
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load';
    }
  }

  const loadIssues = async () => (openIssues = await api<IssueListDto>('/api/issues?state=unacknowledged').catch(() => openIssues));

  const loadEvents = async () => (events = await api<EventStats>(`/api/stats/events?days=14&utcOffsetMinutes=${utcOffsetMinutes()}`).catch(() => events));
  const loadPosture = async () => (posture = await api<PosturePoint[]>(`/api/stats/posture?days=${trendDays}`).catch(() => posture));
  const loadMatrix = async () => (matrix = await api<Matrix>('/api/stats/matrix').catch(() => matrix));

  $effect(() => {
    load();
    loadIssues();
    loadEvents();
    loadMatrix();
    const offs = [
      refreshOn(['hostUpdated', 'eventsCreated', 'bansChanged', 'policyChanged'], load),
      refreshOn(['issuesChanged'], loadIssues),
      refreshOn(['eventsCreated'], loadEvents, 60_000),
      refreshOn(['hostUpdated', 'baselineUpdated', 'policyChanged', 'issuesChanged'], () => { loadMatrix(); loadPosture(); }, 60_000),
    ];
    return () => offs.forEach((o) => o());
  });

  $effect(() => {
    void trendDays;
    loadPosture();
  });

  // Figure sparklines: the last two weeks of the fleet trend.
  const recent = $derived(posture.slice(-14));
  const spark = (pick: (p: PosturePoint) => number | null) => recent.map(pick);
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
          {#if data.averageBaselineScore !== null}<Sparkline values={spark((p) => p.baselineScore)} label="Average baseline score, last 14 days" />{/if}
        </a>
        <a class="ledger-cell" href="/baseline?view=lynis">
          <span class="figure-label">Hardening index</span>
          <span class="figure-value">{#if data.averageHardeningIndex !== null}{data.averageHardeningIndex.toFixed(0)}{:else}<span class="nil" aria-label="none"></span>{/if}</span>
          <span class="figure-foot">{data.averageHardeningIndex === null ? 'not audited yet' : 'Lynis average across hosts'}</span>
          {#if data.averageHardeningIndex !== null}<Sparkline values={spark((p) => p.hardeningIndex)} label="Average hardening index, last 14 days" />{/if}
        </a>
        <a class="ledger-cell" href="/hosts?filter=updates">
          <span class="figure-label">Pending security updates</span>
          <span class="figure-value">{#if data.hostsWithPendingSecurityUpdates !== null}{data.hostsWithPendingSecurityUpdates}{:else}<span class="nil" aria-label="none"></span>{/if}</span>
          <span class="figure-foot">{data.hostsWithPendingSecurityUpdates === null ? 'not checked yet' : `host${data.hostsWithPendingSecurityUpdates === 1 ? '' : 's'} need updates`}</span>
          {#if data.hostsWithPendingSecurityUpdates !== null}<Sparkline values={spark((p) => p.hostsNeedingUpdates)} label="Hosts needing security updates, last 14 days" />{/if}
        </a>
        <a class="ledger-cell" href="/vulnerabilities">
          <span class="figure-label">Critical &amp; high CVEs</span>
          <span class="figure-value">{#if data.hostsWithHighCves !== null}{data.hostsWithHighCves}{:else}<span class="nil" aria-label="none"></span>{/if}</span>
          <span class="figure-foot">{data.hostsWithHighCves === null ? 'not scanned yet' : `host${data.hostsWithHighCves === 1 ? '' : 's'} affected`}</span>
          {#if data.hostsWithHighCves !== null}<Sparkline values={spark((p) => p.hostsWithHighCves)} label="Hosts with critical or high CVEs, last 14 days" />{/if}
        </a>
        <a class="ledger-cell" href="/baseline?view=exposure">
          <span class="figure-label">Public SSH</span>
          <span class="figure-value">{#if data.hostsWithPublicSsh !== null}{data.hostsWithPublicSsh}{:else}<span class="nil" aria-label="none"></span>{/if}</span>
          <span class="figure-foot">{data.hostsWithPublicSsh === null ? 'not checked yet' : `host${data.hostsWithPublicSsh === 1 ? '' : 's'} reachable from the internet`}</span>
          {#if data.hostsWithPublicSsh !== null}<Sparkline values={spark((p) => p.publicSsh)} label="Hosts with public SSH, last 14 days" />{/if}
        </a>
        {#if data.hostsWithPublicServices !== null}
          <a class="ledger-cell" href="/issues?rule=service.public">
            <span class="figure-label">Unexpected public services</span>
            <span class="figure-value" class:bad={data.hostsWithPublicServices > 0}>{data.hostsWithPublicServices}</span>
            <span class="figure-foot">host{data.hostsWithPublicServices === 1 ? '' : 's'} with ports open beyond <code>allowPublicPorts</code></span>
            <Sparkline values={spark((p) => p.hostsWithPublicServices)} label="Hosts with unexpected public services, last 14 days" />
          </a>
        {/if}
        {#if data.hostsWithIntegrityChanges !== null || data.hostsWithRootkitWarnings !== null}
          {@const n = (data.hostsWithIntegrityChanges ?? 0) + (data.hostsWithRootkitWarnings ?? 0)}
          <a class="ledger-cell" href="/issues?rule=integrity.changed">
            <span class="figure-label">File integrity</span>
            <span class="figure-value" class:bad={n > 0}>{n}</span>
            <span class="figure-foot">{data.hostsWithIntegrityChanges ?? 0} with changed files (AIDE), {data.hostsWithRootkitWarnings ?? 0} with rkhunter warnings</span>
          </a>
        {/if}
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

  {#if data.hostsTotal > 0}
    <div class="viz">
      <section class="card">
        <header><h2>Events per day</h2><a class="hint" href="/events">Timeline</a></header>
        <div class="card-body">
          {#if events}<StackedBars title="Last 14 days, by severity" series={severitySeries} buckets={eventBuckets(events)} empty="No events in the last 14 days." />
          {:else}<div class="skeleton-block" style:height="150px"></div>{/if}
        </div>
      </section>
      <section class="card">
        <header>
          <h2>Posture trend</h2>
          <div class="seg" role="group" aria-label="Trend range">
            {#each [[30, '30d'], [90, '90d'], [365, '1y']] as [d, label] (d)}
              <button class:on={trendDays === d} aria-pressed={trendDays === d} onclick={() => (trendDays = d as number)}>{label}</button>
            {/each}
          </div>
        </header>
        <div class="trends">
          <MetricChart title="Baseline score (avg)" points={trend(posture, (p) => p.baselineScore)} max={100} daily height={96} format={counts} />
          <MetricChart title="Hosts with critical/high CVEs" points={trend(posture, (p) => p.hostsWithHighCves)} daily height={96} format={counts} />
          <MetricChart title="Hosts needing security updates" points={trend(posture, (p) => p.hostsNeedingUpdates)} daily height={96} format={counts} />
          <MetricChart title="Exploited CVEs (KEV)" points={trend(posture, (p) => p.vulnKev)} daily height={96} format={counts} />
        </div>
      </section>
    </div>

    {#if matrix && matrix.rows.length}
      <section class="card matrix-card">
        <header><h2>Posture by host</h2><span class="hint">each cell links to the host tab</span></header>
        <PostureMatrix {matrix} />
      </section>
    {/if}
  {/if}

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
        <header>
          <h2>Open issues</h2>
          <a class="hint" href="/issues">{openIssues && openIssues.summary.acknowledged > 0 ? `All issues (${openIssues.summary.acknowledged} acknowledged)` : 'All issues'}</a>
        </header>
        {#if openIssues?.items.length}
          <IssueList issues={openIssues.items.slice(0, 8)} compact onchange={() => { loadIssues(); refreshIssues(); }} />
          {#if openIssues.items.length > 8}<div class="more"><a href="/issues?state=unacknowledged">{openIssues.items.length - 8} more</a></div>{/if}
        {:else if openIssues}
          <div class="empty">{fleet.hosts.length ? 'No open issues. Hosts are online, healthy and match their policy.' : 'No hosts yet.'}</div>
        {:else}
          <div class="skeleton-block" style:height="120px"></div>
        {/if}
      </section>

      <section class="card">
        <header><h2>Top offenders · 24h</h2><span class="hint">ban and auth-failure events</span></header>
        {#if data.topOffenders.length}
          <BarList label="Events per offending IP" items={data.topOffenders.map((o) => ({ key: o.target, label: o.target, value: o.events, href: `/events?ip=${encodeURIComponent(o.target)}`, note: o.hosts > 1 ? `${o.hosts} hosts` : undefined }))} />
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
  .figure-foot :global(code) { font-size: var(--text-xs); }
  .ledger-cell :global(.spark) { margin-top: var(--space-2xs); }
  .viz { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 420px), 1fr)); gap: var(--space-md); align-items: start; margin-bottom: var(--space-md); }
  .trends { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); overflow: hidden; }
  .trends > :global(*) { padding: var(--space-md); box-shadow: 1px 0 0 var(--border), 0 1px 0 var(--border); }
  .matrix-card { margin-bottom: var(--space-lg); overflow: hidden; }
  @media (max-width: 640px) { .trends { grid-template-columns: minmax(0, 1fr); } }
  .columns { display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr); gap: var(--space-md); align-items: start; }
  .host-name { font-family: var(--font-display); font-weight: 500; white-space: nowrap; }
  .ledger-skeleton { height: 280px; margin-bottom: var(--space-lg); }
  @media (max-width: 1100px) { .columns { grid-template-columns: minmax(0, 1fr); } }
  @media (max-width: 760px) {
    .band { grid-template-columns: minmax(0, 1fr); }
    .band-name { box-shadow: 0 1px 0 var(--border); padding: var(--space-sm) var(--space-md); }
  }
</style>
