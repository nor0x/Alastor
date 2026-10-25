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

  // Tile sparklines: the last two weeks of the fleet trend.
  const recent = $derived(posture.slice(-14));
  const spark = (pick: (p: PosturePoint) => number | null) => recent.map(pick);
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
      {#if data.averageBaselineScore !== null}<Sparkline values={spark((p) => p.baselineScore)} label="Average baseline score, last 14 days" />{/if}
    </a>
    <a class="tile" href="/hosts?filter=updates">
      <span class="label">Pending security updates</span>
      <span class="big">{data.hostsWithPendingSecurityUpdates ?? '—'}</span>
      <span class="foot muted">{data.hostsWithPendingSecurityUpdates === null ? 'not checked yet' : `host${data.hostsWithPendingSecurityUpdates === 1 ? '' : 's'} need updates`}</span>
      {#if data.hostsWithPendingSecurityUpdates !== null}<Sparkline values={spark((p) => p.hostsNeedingUpdates)} label="Hosts needing security updates, last 14 days" />{/if}
    </a>
    <a class="tile" href="/vulnerabilities">
      <span class="label">Critical &amp; high CVEs</span>
      <span class="big">{data.hostsWithHighCves ?? '—'}</span>
      <span class="foot muted">{data.hostsWithHighCves === null ? 'not scanned yet' : `host${data.hostsWithHighCves === 1 ? '' : 's'} affected`}</span>
      {#if data.hostsWithHighCves !== null}<Sparkline values={spark((p) => p.hostsWithHighCves)} label="Hosts with critical or high CVEs, last 14 days" />{/if}
    </a>
    <a class="tile" href="/baseline?view=exposure">
      <span class="label">Public SSH</span>
      <span class="big">{data.hostsWithPublicSsh ?? '—'}</span>
      <span class="foot muted">{data.hostsWithPublicSsh === null ? 'not checked yet' : `host${data.hostsWithPublicSsh === 1 ? '' : 's'} reachable from the internet`}</span>
      {#if data.hostsWithPublicSsh !== null}<Sparkline values={spark((p) => p.publicSsh)} label="Hosts with public SSH, last 14 days" />{/if}
    </a>
    {#if data.hostsWithPublicServices !== null}
      <a class="tile" href="/issues?rule=service.public">
        <span class="label">Unexpected public services</span>
        <span class="big">{data.hostsWithPublicServices}</span>
        <span class="foot muted">host{data.hostsWithPublicServices === 1 ? '' : 's'} with ports open to the internet beyond <code>allowPublicPorts</code></span>
        <Sparkline values={spark((p) => p.hostsWithPublicServices)} label="Hosts with unexpected public services, last 14 days" />
      </a>
    {/if}
    {#if data.hostsWithIntegrityChanges !== null || data.hostsWithRootkitWarnings !== null}
      <a class="tile" href="/issues?rule=integrity.changed">
        <span class="label">File integrity</span>
        <span class="big" class:bad={(data.hostsWithIntegrityChanges ?? 0) + (data.hostsWithRootkitWarnings ?? 0) > 0}>{(data.hostsWithIntegrityChanges ?? 0) + (data.hostsWithRootkitWarnings ?? 0)}</span>
        <span class="foot muted">{data.hostsWithIntegrityChanges ?? 0} with changed files (AIDE) · {data.hostsWithRootkitWarnings ?? 0} with rkhunter warnings</span>
      </a>
    {/if}
    {#if data.hostsWithMalware !== null}
      <a class="tile" href="/hosts">
        <span class="label">Malware</span>
        <span class="big" class:bad={data.hostsWithMalware > 0}>{data.hostsWithMalware}</span>
        <span class="foot muted">host{data.hostsWithMalware === 1 ? '' : 's'} with infected files (ClamAV)</span>
      </a>
    {/if}
    <a class="tile" href="/baseline?view=lynis">
      <span class="label">Hardening index</span>
      <span class="big">{data.averageHardeningIndex?.toFixed(0) ?? '—'}</span>
      <span class="foot muted">{data.averageHardeningIndex === null ? 'not audited yet' : 'Lynis average across hosts'}</span>
      {#if data.averageHardeningIndex !== null}<Sparkline values={spark((p) => p.hardeningIndex)} label="Average hardening index, last 14 days" />{/if}
    </a>
  </section>

  {#if data.hostsTotal > 0}
    <div class="grid-2 viz">
      <section class="card">
        <header><h2>Events per day</h2><a class="hint" href="/events">Timeline →</a></header>
        <div class="card-body">
          {#if events}<StackedBars title="Last 14 days, by severity" series={severitySeries} buckets={eventBuckets(events)} empty="No events in the last 14 days." />
          {:else}<div class="skeleton-block" style="height:150px"></div>{/if}
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
        <div class="card-body trends">
          <MetricChart title="Baseline score (avg)" points={trend(posture, (p) => p.baselineScore)} max={100} daily height={96} format={counts} />
          <MetricChart title="Hosts with critical/high CVEs" points={trend(posture, (p) => p.hostsWithHighCves)} daily height={96} format={counts} />
          <MetricChart title="Hosts needing security updates" points={trend(posture, (p) => p.hostsNeedingUpdates)} daily height={96} format={counts} />
          <MetricChart title="Exploited CVEs (KEV)" points={trend(posture, (p) => p.vulnKev)} daily height={96} format={counts} />
        </div>
      </section>
    </div>

    {#if matrix && matrix.rows.length}
      <section class="card matrix-card">
        <header><h2>Posture by host</h2><span class="hint">click a cell for details</span></header>
        <PostureMatrix {matrix} />
      </section>
    {/if}
  {/if}

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
        <header>
          <h2>Open issues</h2>
          <a class="hint" href="/issues">{openIssues && openIssues.summary.acknowledged > 0 ? `All issues (${openIssues.summary.acknowledged} acknowledged) →` : 'All issues →'}</a>
        </header>
        {#if openIssues?.items.length}
          <IssueList issues={openIssues.items.slice(0, 8)} compact onchange={() => { loadIssues(); refreshIssues(); }} />
          {#if openIssues.items.length > 8}<div class="more"><a href="/issues?state=unacknowledged">{openIssues.items.length - 8} more →</a></div>{/if}
        {:else if openIssues}
          <div class="empty">{fleet.hosts.length ? 'No open issues. Hosts are online, healthy and match their policy.' : 'No hosts yet.'}</div>
        {:else}
          <div class="skeleton-block" style="height:120px"></div>
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
  .big.bad { color: var(--bad); }
  .of { font-size: 16px; color: var(--muted); font-weight: 400; margin-left: 4px; }
  .foot { font-size: 12px; display: inline-flex; align-items: center; gap: 6px; }
  .foot.bad { color: var(--bad); }
  .foot.warn { color: var(--warn); }
  .viz { margin-bottom: 16px; }
  .trends { display: grid; grid-template-columns: 1fr 1fr; gap: 16px 20px; }
  .matrix-card { margin-bottom: 16px; }
  .matrix-card :global(.table-wrap) { padding: 4px 8px 8px; }
  .tile :global(.spark) { margin-top: 6px; }
  @media (max-width: 640px) { .trends { grid-template-columns: 1fr; } }
  .more { padding: 8px 16px; border-top: 1px solid var(--border); font-size: 12px; }
</style>
