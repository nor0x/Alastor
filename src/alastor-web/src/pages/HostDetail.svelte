<script lang="ts">
  import { api, errorText, type Ban, type BanHour, type Command, type EventPage, type EventStats, type HostDetail, type IssueList as IssueListDto, type PosturePoint, type MetricPoint, type SecurityEvent, type ToolStatus } from '../lib/api';
  import { fleet, refreshFleet } from '../lib/fleet.svelte';
  import { on, refreshOn } from '../lib/live.svelte';
  import { navigate, route } from '../lib/router.svelte';
  import { canWrite } from '../lib/session.svelte';
  import { toast } from '../lib/toast.svelte';
  import { bytes, fullDate, liveUptime, uptime } from '../lib/format';
  import { rebootHost } from '../lib/hostActions';
  import { clock } from '../lib/ui/clock.svelte';
  import { scoreTone } from '../lib/baseline';
  import { confirm } from '../lib/ui/confirm.svelte';
  import BanDialog from '../lib/BanDialog.svelte';
  import BanTable from '../lib/BanTable.svelte';
  import HostBaseline from '../lib/HostBaseline.svelte';
  import HostUpdates from '../lib/HostUpdates.svelte';
  import HostSoftware from '../lib/HostSoftware.svelte';
  import HostStorage from '../lib/HostStorage.svelte';
  import HostVulnerabilities from '../lib/HostVulnerabilities.svelte';
  import HostHardening from '../lib/HostHardening.svelte';
  import HostNetwork from '../lib/HostNetwork.svelte';
  import HostMalware from '../lib/HostMalware.svelte';
  import HostLogins from '../lib/HostLogins.svelte';
  import HostIntegrity from '../lib/HostIntegrity.svelte';
  import { exposureLook, isExposed } from '../lib/network';
  import { indexTone } from '../lib/hardening';
  import { diskTone } from '../lib/storage';
  import UpdatesBadge from '../lib/ui/UpdatesBadge.svelte';
  import VulnBadge from '../lib/ui/VulnBadge.svelte';
  import EventList from '../lib/ui/EventList.svelte';
  import IssueList from '../lib/IssueList.svelte';
  import { refreshIssues } from '../lib/issues.svelte';
  import { banBuckets, banSeries, counts, eventBuckets, trend } from '../lib/stats';
  import { severitySeries, utcOffsetMinutes } from '../lib/ui/chart';
  import StackedBars from '../lib/ui/StackedBars.svelte';
  import MetricChart from '../lib/ui/MetricChart.svelte';
  import Modal from '../lib/ui/Modal.svelte';
  import Time from '../lib/ui/Time.svelte';
  import Icon from '../lib/ui/Icon.svelte';

  let { id }: { id: string } = $props();

  type Tab = 'overview' | 'baseline' | 'hardening' | 'network' | 'updates' | 'software' | 'storage' | 'vulnerabilities' | 'malware' | 'integrity' | 'events' | 'bans' | 'policy' | 'commands';
  const tabs: [Tab, string][] = [['overview', 'Overview'], ['baseline', 'Baseline'], ['hardening', 'Hardening'], ['network', 'Network'], ['updates', 'Updates'], ['software', 'Software'], ['storage', 'Storage'], ['vulnerabilities', 'CVEs'], ['malware', 'Malware'], ['integrity', 'Integrity'], ['events', 'Events'], ['bans', 'Bans'], ['policy', 'Policy'], ['commands', 'Commands']];
  const tab = $derived((new URLSearchParams(route.search).get('tab') as Tab) || 'overview');

  let host = $state<HostDetail | null>(null);
  let notFound = $state(false);
  let error = $state('');
  let hours = $state(6);
  let metrics = $state<MetricPoint[]>([]);
  let events = $state<SecurityEvent[]>([]);
  let eventsNext = $state<string | null>(null);
  let bans = $state<Ban[]>([]);
  let hostIssues = $state<IssueListDto | null>(null);
  let eventStats = $state<EventStats | null>(null);
  let banHours = $state<BanHour[]>([]);
  let posture = $state<PosturePoint[]>([]);
  let commands = $state<Command[]>([]);
  let effective = $state<{ revision: string; yaml: string; layers: { layerId: string; scope: string; targetId: string | null; version: number }[] } | null>(null);
  let banOpen = $state(false);
  let editOpen = $state(false);

  async function loadHost() {
    try {
      host = await api<HostDetail>(`/api/hosts/${id}`);
      error = '';
    } catch (e) {
      if (e instanceof Error && 'status' in e && (e as { status: number }).status === 404) notFound = true;
      else error = errorText(e);
    }
  }
  const loadMetrics = async () => (metrics = await api<MetricPoint[]>(`/api/hosts/${id}/metrics?hours=${hours}`).catch(() => metrics));
  const loadIssues = async () => (hostIssues = await api<IssueListDto>(`/api/issues?hostId=${id}`).catch(() => hostIssues));
  async function loadStats() {
    const [e, b, p] = await Promise.all([
      api<EventStats>(`/api/stats/events?hostId=${id}&days=14&utcOffsetMinutes=${utcOffsetMinutes()}`).catch(() => eventStats),
      api<BanHour[]>(`/api/stats/bans?hostId=${id}&hours=24`).catch(() => banHours),
      api<PosturePoint[]>(`/api/stats/posture?hostId=${id}&days=90`).catch(() => posture),
    ]);
    eventStats = e;
    banHours = b;
    posture = p;
  }
  const loadBans = async () => (bans = await api<Ban[]>(`/api/bans?hostId=${id}`).catch(() => bans));
  const loadCommands = async () => (commands = await api<Command[]>(`/api/hosts/${id}/commands`).catch(() => commands));
  const loadEffective = async () => (effective = await api<typeof effective>(`/api/hosts/${id}/effective-policy`).catch(() => effective));
  async function loadEvents(more = false) {
    const p = new URLSearchParams({ hostId: id, limit: '50' });
    if (more && eventsNext) p.set('before', eventsNext);
    const page = await api<EventPage>(`/api/events?${p}`).catch(() => null);
    if (!page) return;
    events = more ? [...events, ...page.items] : page.items;
    eventsNext = page.nextBefore;
  }

  // Reload everything when the route's host changes.
  $effect(() => {
    void id;
    host = null;
    notFound = false;
    loadHost();
    loadMetrics();
    loadBans();
    loadIssues();
    loadStats();
    loadEvents();
    loadCommands();
    loadEffective();
  });

  $effect(() => {
    void hours;
    loadMetrics();
  });

  $effect(() => {
    const offs = [
      refreshOn(['policyChanged'], () => { loadHost(); loadEffective(); }),
      refreshOn(['issuesChanged'], loadIssues),
      refreshOn(['eventsCreated', 'baselineUpdated'], loadStats, 60_000),
      on('hostUpdated', (h: { id: string }) => {
        if (h.id !== id) return;
        loadHost();
        loadMetrics();
      }),
      on('bansChanged', (hostId: string) => hostId === id && loadBans()),
      on('eventsCreated', (list: SecurityEvent[]) => {
        const mine = list.filter((e) => e.hostId === id);
        if (mine.length) events = [...mine.reverse(), ...events.filter((e) => !mine.some((m) => m.id === e.id))];
      }),
      on('commandUpdated', (c: Command) => {
        if (c.hostId !== id) return;
        const i = commands.findIndex((x) => x.id === c.id);
        if (i >= 0) commands[i] = c;
        else commands = [c, ...commands];
      }),
    ];
    // Polling fallback for host + metrics while the hub is down.
    const poll = refreshOn([], () => { loadHost(); loadMetrics(); }, 30_000);
    return () => { offs.forEach((o) => o()); poll(); };
  });

  function setTab(t: Tab) {
    navigate(t === 'overview' ? `/hosts/${id}` : `/hosts/${id}?tab=${t}`, true);
  }

  async function action(name: 'reconcile' | 'reclaim' | 'refresh-bans', label: string) {
    if (name === 'reclaim' && !(await confirm('Reclaim managed files?', 'Hand edits to files Alastor manages on this host are overwritten with the policy. A backup is kept until the apply succeeds.', { confirmLabel: 'Reclaim', danger: true }))) return;
    try {
      const cmd = await api<Command>(`/api/hosts/${id}/actions/${name}`, { method: 'POST' });
      commands = [cmd, ...commands.filter((c) => c.id !== cmd.id)];
      toast(`${label} queued. ${host?.summary.isOnline ? 'The agent picks it up within seconds.' : 'The host is offline; it runs when the agent reconnects.'}`);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  async function reboot() {
    if (!host) return;
    const cmd = await rebootHost(host.summary);
    if (cmd) commands = [cmd, ...commands.filter((c) => c.id !== cmd.id)];
  }

  async function remove() {
    if (!host) return;
    const ok = await confirm(
      `Remove ${host.summary.name}?`,
      'The agent secret is revoked immediately and the host disappears from the dashboard with its bans and metrics.\n\nOn the server itself, run "sudo alastor-agent uninstall" to remove the agent and the configuration it manages.',
      { confirmLabel: 'Remove host', danger: true },
    );
    if (!ok) return;
    try {
      await api(`/api/hosts/${id}`, { method: 'DELETE' });
      await refreshFleet();
      toast(`${host.summary.name} removed.`);
      navigate('/hosts');
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  // ---- Edit host (name, group, tags) ----
  let editName = $state('');
  let editGroup = $state('');
  let editTags = $state('');
  let editBusy = $state(false);
  function openEdit() {
    if (!host) return;
    editName = host.summary.name;
    editGroup = host.summary.groupId ?? '';
    editTags = host.summary.tags.join(', ');
    editOpen = true;
  }
  async function saveEdit(e: SubmitEvent) {
    e.preventDefault();
    editBusy = true;
    try {
      await api(`/api/hosts/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: editName.trim(),
          groupId: editGroup || null,
          clearGroup: !editGroup,
          tags: editTags.split(',').map((t) => t.trim()).filter(Boolean),
        }),
      });
      editOpen = false;
      toast('Host updated. A group change re-applies the effective policy.');
      loadHost();
      refreshFleet();
    } catch (err) {
      toast(errorText(err), 'error');
    } finally {
      editBusy = false;
    }
  }

  // ---- Capability matrix helpers ----
  function toolState(t: ToolStatus): { tone: string; label: string } {
    if (!t.implemented) return { tone: 'muted', label: 'coming later' };
    if (t.availability === 'Disabled') return { tone: 'muted', label: t.optIn ? 'opt-in, off' : 'disabled' };
    if (t.availability === 'Unavailable') return { tone: 'bad', label: 'unavailable' };
    if (!t.installed) return { tone: 'warn', label: 'not installed' };
    if (!t.running) return { tone: 'bad', label: 'stopped' };
    return { tone: 'ok', label: 'running' };
  }
  const configHelp: Record<string, string> = {
    InSync: 'Configuration matches the policy.',
    Pending: 'The latest policy has not been applied yet.',
    Drifted: 'Someone edited a file Alastor manages. It is left alone until you reclaim it.',
    Conflict: 'A hand-written config defines the same settings. The overlapping part is skipped; set takeover: true in the policy to manage it.',
    Rejected: 'The tool rejected the last config and the agent rolled back to the previous one.',
    Unknown: '',
  };
  const configTone: Record<string, string> = { InSync: 'ok', Pending: 'info', Drifted: 'warn', Conflict: 'warn', Rejected: 'bad', Unknown: 'muted' };

  const implemented = $derived(host?.tools.filter((t) => t.implemented) ?? []);
  const planned = $derived(host?.tools.filter((t) => !t.implemented) ?? []);
  const series = (key: 'cpu' | 'memory' | 'disk' | 'load1') => metrics.map((m) => ({ at: m.at, value: m[key] }));
  const commandTone: Record<string, string> = { Pending: 'muted', Delivered: 'info', Succeeded: 'ok', Failed: 'bad', Expired: 'warn' };
</script>

{#if notFound}
  <div class="empty empty-dashed">
    This host doesn’t exist (it may have been removed). <a href="/hosts">Back to hosts</a>
  </div>
{:else if error && !host}
  <div class="banner bad" role="alert"><Icon name="error" /><p>Couldn’t load the host: {error}</p></div>
{:else if !host}
  <div class="skeleton-block"></div>
{:else}
  {@const s = host.summary}
  <div class="crumbs"><a href="/hosts">Hosts</a> /</div>
  <div class="page-head">
    <div class="head-text">
      <h1>{s.name}</h1>
      <div class="sysline">
        {#if s.isOnline}<span class="pill ok">online</span>
        {:else}<span class="pill bad">offline, last seen <Time iso={s.lastSeenAt} /></span>{/if}
        <span>{s.osPrettyName}</span>
        <span class="mono">{s.architecture}</span>
        <span>agent <span class="mono">{s.agentVersion}</span></span>
        {#if s.groupName}<span>group <span class="pill tag">{s.groupName}</span></span>{/if}
        {#if s.tags.length}<span class="tags">{#each s.tags as t (t)}<span class="pill tag">{t}</span>{/each}</span>{/if}
      </div>
    </div>
    {#if canWrite()}
      <div class="actions">
        <button class="btn" onclick={() => action('reconcile', 'Re-apply policy')} title="Run the reconcile loop now">Re-apply policy</button>
        <button class="btn" onclick={() => action('refresh-bans', 'Ban list refresh')}>Refresh bans</button>
        <button class="btn" onclick={openEdit}>Edit</button>
        <button class="btn danger" onclick={reboot} disabled={!s.isOnline} title={s.isOnline ? 'Reboot this host in one minute' : 'The host is offline'}>Reboot</button>
        <button class="btn danger" onclick={remove}>Remove</button>
      </div>
    {/if}
  </div>

  {#if host.policyApplySuccess === false}
    <div class="banner bad spaced" role="alert">
      <Icon name="error" />
      <p><strong>The last policy apply failed.</strong> The agent rolled back to the previous working config. See the Policy tab for the tool’s error.</p>
    </div>
  {/if}
  {#if implemented.some((t) => t.configState === 'Drifted')}
    <div class="banner warn spaced">
      <Icon name="alert" />
      <p><strong>Managed config was edited by hand.</strong> Alastor won’t overwrite it until you reclaim it.</p>
      {#if canWrite()}<button class="btn small" onclick={() => action('reclaim', 'Reclaim')}>Reclaim</button>{/if}
    </div>
  {/if}

  <nav class="tabs" aria-label="Host sections">
    {#each tabs as [t, label] (t)}
      <button class:on={tab === t} aria-current={tab === t ? 'page' : undefined} onclick={() => setTab(t)}>
        {label}
        {#if t === 'baseline' && s.baselineFailing}<span class="count">{s.baselineFailing}</span>{/if}
        {#if t === 'updates' && (s.securityUpdates ?? s.pendingUpdates)}<span class="count">{s.securityUpdates ?? s.pendingUpdates}</span>{/if}
        {#if t === 'network' && isExposed(s.sshExposure, s.sshExposureAccepted)}<span class="count alert" title="SSH reachable from the internet"><Icon name="alert" size={12} label="SSH reachable from the internet" /></span>{/if}
        {#if t === 'integrity' && (s.integrityChanges || s.rootkitWarnings)}<span class="count" title="Files changed since the baseline, and open rkhunter warnings">{(s.integrityChanges ?? 0) + (s.rootkitWarnings ?? 0)}</span>{/if}
        {#if t === 'malware' && s.malwareFindings}<span class="count" title="Infected files found by ClamAV">{s.malwareFindings}</span>{/if}
        {#if t === 'hardening' && s.hardeningWarnings}<span class="count">{s.hardeningWarnings}</span>{/if}
        {#if t === 'vulnerabilities' && (s.vulnCritical ?? 0) + (s.vulnHigh ?? 0) > 0}<span class="count">{(s.vulnCritical ?? 0) + (s.vulnHigh ?? 0)}</span>{/if}
        {#if t === 'bans' && bans.length}<span class="count">{bans.length}</span>{/if}
        {#if t === 'commands' && commands.some((c) => c.status === 'Pending' || c.status === 'Delivered')}<span class="count">…</span>{/if}
      </button>
    {/each}
  </nav>

  {#if tab === 'overview'}
    <div class="stack">
      {#if hostIssues?.items.length}
        <section class="card">
          <header><h2>Open issues</h2><a class="hint" href="/issues?hostId={id}">History</a></header>
          <IssueList issues={hostIssues.items} showHost={false} onchange={() => { loadIssues(); refreshIssues(); }} />
        </section>
      {/if}
      <section class="card">
        <header>
          <h2>Live metrics</h2>
          <div class="seg" role="group" aria-label="Time range">
            {#each [[1, '1h'], [6, '6h'], [24, '24h'], [168, '7d']] as [h, label] (h)}
              <button class:on={hours === h} aria-pressed={hours === h} onclick={() => (hours = h as number)}>{label}</button>
            {/each}
          </div>
        </header>
        <div class="charts">
          <MetricChart title="CPU" points={series('cpu')} max={100} />
          <MetricChart title="Memory" detail="{bytes(host.memoryUsedBytes)} of {bytes(host.memoryTotalBytes)}" points={series('memory')} max={100} />
          <MetricChart title="Disk" detail="{bytes(host.diskUsedBytes)} of {bytes(host.diskTotalBytes)}" points={series('disk')} max={100} />
          <MetricChart title="Load (1 min)" points={series('load1')} unit="" />
        </div>
      </section>

      <section class="card">
        <header><h2>Security posture</h2><span class="hint">events and bans on this host, 90-day trends</span></header>
        <div class="charts posture-bars">
          {#if eventStats}<StackedBars title="Events per day · 14 days" series={severitySeries} buckets={eventBuckets(eventStats)} height={140} empty="No events in the last 14 days." />{/if}
          <StackedBars title="Bans per hour · 24 hours" series={banSeries} buckets={banBuckets(banHours)} height={140} empty="No bans or auth failures in the last 24 hours." />
        </div>
        <div class="charts posture">
          <MetricChart title="Baseline score" points={trend(posture, (p) => p.baselineScore)} max={100} daily height={96} format={counts} />
          <MetricChart title="Critical + high CVEs" points={trend(posture, (p) => (p.vulnCritical === null ? null : p.vulnCritical + (p.vulnHigh ?? 0)))} daily height={96} format={counts} />
          <MetricChart title="Pending security updates" points={trend(posture, (p) => p.securityUpdates)} daily height={96} format={counts} />
          <MetricChart title="Hardening index" points={trend(posture, (p) => p.hardeningIndex)} max={100} daily height={96} format={counts} />
        </div>
      </section>

      <div class="overview-grid">
        <section class="card">
          <header><h2>Capability matrix</h2><span class="hint">what the agent runs on this host</span></header>
          <ul class="tools">
            {#each implemented as t (t.toolId)}
              {@const st = toolState(t)}
              <li>
                <div class="tool-head">
                  <div class="tool-name">
                    <strong>{t.displayName}</strong>
                    <span class="tool-sub"><span>{t.capability}</span>{#if t.version}<span class="mono">v{t.version}</span>{/if}</span>
                  </div>
                  <span class="pill {st.tone}">{st.label}</span>
                </div>
                <div class="tool-meta">
                  {#if t.installed}
                    <span class="pill muted" title={t.ownership === 'Adopted' ? 'Was installed before Alastor; the agent manages only its own files.' : 'Installed by Alastor.'}>{t.ownership === 'Adopted' ? 'adopted existing install' : 'installed by Alastor'}</span>
                    <span class="pill {configTone[t.configState]}" title={configHelp[t.configState]}>config: {t.configState === 'InSync' ? 'in sync' : t.configState.toLowerCase()}</span>
                  {/if}
                  {#each Object.entries(t.details) as [k, v] (k)}<span class="detail">{k} <span class="mono">{v}</span></span>{/each}
                </div>
                {#if t.unavailableReason && t.availability !== 'Available'}<p class="note">{t.unavailableReason}</p>{/if}
                {#if configHelp[t.configState] && t.configState !== 'InSync' && t.installed}<p class="note">{configHelp[t.configState]}</p>{/if}
                {#if t.lastError}<p class="note bad"><Icon name="error" />{t.lastError}</p>{/if}
                {#each t.warnings as w (w)}<p class="note warn"><Icon name="alert" />{w}</p>{/each}
              </li>
            {/each}
          </ul>
          {#if planned.length}
            <details class="planned">
              <summary>{planned.length} more integrations planned</summary>
              <p class="muted small">{planned.map((t) => t.displayName).join(', ')}</p>
            </details>
          {/if}
        </section>

        <section class="card">
          <header><h2>System</h2></header>
          <dl class="kv facts">
            <dt>Hostname</dt><dd class="mono">{s.hostname}</dd>
            <dt>IP addresses</dt><dd class="mono">{#if host.ipAddresses.length}{host.ipAddresses.join(', ')}{:else}<span class="nil" aria-label="none"></span>{/if}</dd>
            <dt>OS</dt><dd>{s.osPrettyName} <span class="muted">({host.osId} {host.osVersion})</span></dd>
            <dt>Kernel</dt><dd class="mono">{host.kernelVersion}</dd>
            <dt>Uptime</dt><dd>{#if liveUptime(s, clock.now) !== null}{uptime(liveUptime(s, clock.now) ?? 0)}{:else}{uptime(host.uptimeSeconds)} <span class="muted small">when last seen</span>{/if}</dd>
            <dt>Load</dt><dd class="mono load"><span title="1 min">{s.load1.toFixed(2)}</span><span title="5 min">{host.load5.toFixed(2)}</span><span title="15 min">{host.load15.toFixed(2)}</span></dd>
            <dt>Enrolled</dt><dd>{fullDate(host.enrolledAt)}</dd>
            <dt>Last heartbeat</dt><dd><Time iso={s.lastSeenAt} /></dd>
            <dt>Machine ID</dt><dd class="mono small">{#if host.machineId}{host.machineId}{:else}<span class="nil" aria-label="none"></span>{/if}</dd>
          </dl>
          <dl class="kv facts posture">
            <dt>Baseline</dt>
            <dd>
              {#if s.baselineScore !== null}
                <a href="/hosts/{id}?tab=baseline"><span class="pill {scoreTone(s.baselineScore)}">score {s.baselineScore}</span></a>
                {#if s.baselineFailing}<span class="muted small">{s.baselineFailing} failing</span>{/if}
              {:else}<span class="muted">not checked yet</span>{/if}
            </dd>
            <dt>Hardening</dt>
            <dd>
              {#if s.hardeningIndex !== null}
                <a href="/hosts/{id}?tab=hardening"><span class="pill {indexTone(s.hardeningIndex)}">index {s.hardeningIndex}</span></a>
                {#if s.hardeningWarnings}<span class="muted small">{s.hardeningWarnings} warning{s.hardeningWarnings === 1 ? '' : 's'}</span>{/if}
              {:else}<span class="muted">not audited yet</span>{/if}
            </dd>
            <dt>SSH exposure</dt>
            <dd>
              <a href="/hosts/{id}?tab=network"><span class="pill {exposureLook(s.sshExposure, s.sshExposureAccepted).tone}">{exposureLook(s.sshExposure, s.sshExposureAccepted).label}</span></a>
              {#if s.tailscaleState === 'Running'}<span class="pill ok">tailscale</span>{/if}
            </dd>
            <dt>Updates</dt>
            <dd>
              {#if s.pendingUpdates !== null}
                <a href="/hosts/{id}?tab=updates"><UpdatesBadge pending={s.pendingUpdates} security={s.securityUpdates} /></a>
                {#if s.rebootRequired}<span class="pill warn">reboot required</span>{/if}
              {:else}<span class="muted">not checked yet</span>{/if}
            </dd>
            <dt>Disk</dt>
            <dd>
              <a href="/hosts/{id}?tab=storage"><span class="pill {diskTone(s.diskPercent)}">{s.diskPercent.toFixed(0)}% used</span></a>
              <span class="muted small">{bytes(host.diskTotalBytes - host.diskUsedBytes)} free</span>
            </dd>
            <dt>Vulnerabilities</dt>
            <dd>
              {#if s.vulnTotal !== null}
                <a href="/hosts/{id}?tab=vulnerabilities"><VulnBadge critical={s.vulnCritical} high={s.vulnHigh} total={s.vulnTotal} /></a>
                {#if s.vulnFixable}<span class="muted small">{s.vulnFixable} fixable</span>{/if}
              {:else}<span class="muted">not scanned yet</span>{/if}
            </dd>
            <dt>Policy</dt>
            <dd>
              {#if s.policySync === 'in-sync'}<span class="pill ok">in sync</span>{:else if s.policySync === 'failed'}<span class="pill bad">failed</span>{:else}<span class="pill info">pending</span>{/if}
              <span class="mono small muted">rev {host.appliedRevision ?? 'none'}</span>
            </dd>
          </dl>
        </section>
      </div>
    </div>
  {:else if tab === 'baseline'}
    <HostBaseline hostId={id} groupId={s.groupId} groupName={s.groupName} isOnline={s.isOnline} />
  {:else if tab === 'hardening'}
    <HostHardening hostId={id} isOnline={s.isOnline} osId={host.osId} />
  {:else if tab === 'network'}
    <HostNetwork hostId={id} isOnline={s.isOnline} />
    <div class="logins"><HostLogins hostId={id} /></div>
  {:else if tab === 'integrity'}
    <HostIntegrity hostId={id} isOnline={s.isOnline} />
  {:else if tab === 'updates'}
    <HostUpdates hostId={id} isOnline={s.isOnline} />
  {:else if tab === 'software'}
    <HostSoftware hostId={id} hostName={s.name} isOnline={s.isOnline} />
  {:else if tab === 'storage'}
    <HostStorage hostId={id} hostName={s.name} isOnline={s.isOnline} />
  {:else if tab === 'vulnerabilities'}
    <HostVulnerabilities hostId={id} isOnline={s.isOnline} osId={host.osId} />
  {:else if tab === 'malware'}
    <HostMalware hostId={id} isOnline={s.isOnline} osId={host.osId} />
  {:else if tab === 'events'}
    <section class="card">
      <header><h2>Events</h2><a class="hint" href="/events?hostId={id}">Open in event timeline</a></header>
      {#if events.length}
        <EventList {events} showHost={false} />
        {#if eventsNext}<div class="more"><button class="btn" onclick={() => loadEvents(true)}>Load older</button></div>{/if}
      {:else}
        <div class="empty">No events from this host yet.</div>
      {/if}
    </section>
  {:else if tab === 'bans'}
    <section class="card table-wrap">
      <header>
        <h2>Active bans</h2>
        {#if canWrite()}<button class="btn small" onclick={() => (banOpen = true)}>+ Ban IP on this host</button>{/if}
      </header>
      {#if bans.length}
        <BanTable {bans} showHost={false} />
      {:else}
        <div class="empty">No active bans on this host.</div>
      {/if}
    </section>
  {:else if tab === 'policy'}
    <div class="policy-grid">
      <section class="card">
        <header>
          <h2>Last apply</h2>
          {#if host.policyAppliedAt}<span class="hint"><Time iso={host.policyAppliedAt} /></span>{/if}
        </header>
        <div class="card-body stack">
          <dl class="kv">
            <dt>Desired revision</dt><dd class="mono">{host.desiredRevision}</dd>
            <dt>Applied revision</dt><dd class="mono">{#if host.appliedRevision}{host.appliedRevision}{:else}<span class="nil" aria-label="none"></span>{/if}</dd>
          </dl>
          {#if host.policyReport}
            <ul class="reports">
              {#each host.policyReport.tools as r (r.toolId)}
                <li>
                  <div class="tool-head">
                    <strong class="mono">{r.toolId}</strong>
                    <span class="pill {r.success ? configTone[r.state] : 'bad'}">{r.success ? (r.state === 'InSync' ? 'in sync' : r.state.toLowerCase()) : 'failed'}</span>
                  </div>
                  {#if r.error}<pre class="code-block err">{r.error}</pre>{/if}
                  {#if r.changes.length}<ul class="changes small">{#each r.changes as c (c)}<li>{c}</li>{/each}</ul>{:else}<p class="muted small">No changes needed.</p>{/if}
                  {#each r.warnings as w (w)}<p class="note warn"><Icon name="alert" />{w}</p>{/each}
                </li>
              {/each}
            </ul>
          {:else}
            <p class="muted">The agent has not reported an apply yet.</p>
          {/if}
        </div>
      </section>
      <section class="card">
        <header>
          <h2>Effective policy</h2>
          <a class="hint" href="/policies/host/{id}">{canWrite() ? 'Edit host overrides' : 'View host layer'}</a>
        </header>
        <div class="card-body">
          {#if effective}
            <div class="layers">
              <span class="muted small">Merged from</span>
              <ol>
                {#each effective.layers as l (l.layerId)}
                  <li><a href={l.scope === 'Global' ? '/policies/global' : `/policies/${l.scope.toLowerCase()}/${l.targetId}`}>{l.scope === 'Global' ? 'global' : l.scope === 'Group' ? `group ${s.groupName ?? ''}` : 'this host'} <span class="mono">v{l.version}</span></a></li>
                {/each}
              </ol>
            </div>
            <div class="doc">
              <div class="doc-head"><span class="mono">effective.yaml</span><span class="mono">{effective.revision}</span></div>
              <pre class="code-block yaml">{effective.yaml}</pre>
            </div>
          {:else}
            <div class="skeleton-block"></div>
          {/if}
        </div>
      </section>
    </div>
  {:else if tab === 'commands'}
    <section class="card table-wrap">
      <header><h2>Commands</h2><span class="hint">last 50 actions sent to this agent</span></header>
      {#if commands.length}
        <table class="table">
          <thead><tr><th>Command</th><th>Status</th><th class="hide-sm">By</th><th>Queued</th><th>Result</th></tr></thead>
          <tbody>
            {#each commands as c (c.id)}
              <tr>
                <td class="nowrap"><span class="mono">{c.type}</span> {#if c.payload.target}<span class="mono muted">{c.payload.target}</span>{/if}</td>
                <td><span class="pill {commandTone[c.status]}">{c.status.toLowerCase()}</span></td>
                <td class="hide-sm">{c.createdBy}</td>
                <td class="nowrap"><Time iso={c.createdAt} /></td>
                <td class="small">{c.resultMessage ?? ''}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <div class="empty">No commands sent yet.</div>
      {/if}
    </section>
  {/if}

  <BanDialog bind:open={banOpen} hostIds={[id]} />

  <Modal bind:open={editOpen} title="Edit host">
    <form id="edit-host" class="form" onsubmit={saveEdit}>
      <label>Display name <input class="field" bind:value={editName} maxlength="128" required /></label>
      <label>
        Group
        <select class="field" bind:value={editGroup}>
          <option value="">No group</option>
          {#each fleet.groups as g (g.id)}<option value={g.id}>{g.name}</option>{/each}
        </select>
      </label>
      <p class="help">The group decides which group policy layer applies. Manage groups under <a href="/settings/groups">Settings</a>.</p>
      <label>Tags <input class="field" bind:value={editTags} placeholder="web, production" /></label>
      <p class="help">Comma-separated, lowercase, up to 20.</p>
    </form>
    {#snippet footer()}
      <button class="btn" onclick={() => (editOpen = false)}>Cancel</button>
      <button class="btn primary" form="edit-host" disabled={editBusy}>Save</button>
    {/snippet}
  </Modal>
{/if}

<style>
  .logins { margin-top: var(--space-md); }
  .posture-bars { grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr)); }
  .posture { border-top: var(--rule-hair) solid var(--border); }
  .head-text { display: flex; flex-direction: column; gap: var(--space-sm); min-width: 0; }
  .sysline { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-xs) 0; color: var(--muted); }
  .sysline > * + * { margin-left: var(--space-sm); padding-left: var(--space-sm); box-shadow: inset 1px 0 0 var(--border-strong); }
  .sysline .mono { color: var(--text-strong); }
  .tags { display: inline-flex; gap: var(--space-2xs); }
  .spaced { margin-bottom: var(--space-sm); align-items: center; }
  .spaced p { flex: 1; }
  .spaced :global(svg) { color: var(--c, currentColor); }
  .banner.bad { --c: var(--bad); }
  .banner.warn { --c: var(--warn); }
  .count.alert { display: inline-grid; place-items: center; background: var(--bad-bg); color: var(--bad); }
  .charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 220px), 1fr)); }
  .charts > :global(*) { padding: var(--space-md); box-shadow: 1px 0 0 var(--border), 0 1px 0 var(--border); }
  .charts { overflow: hidden; }
  .overview-grid { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr); gap: var(--space-md); align-items: start; }
  .policy-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.2fr); gap: var(--space-md); align-items: start; }
  .tools { list-style: none; margin: 0; padding: 0; }
  .tools li { padding: var(--space-sm) var(--space-md); border-bottom: var(--rule-hair) solid var(--border); }
  .tool-head { display: flex; justify-content: space-between; align-items: center; gap: var(--space-xs); }
  .tool-name { display: flex; flex-wrap: wrap; align-items: baseline; gap: var(--space-2xs) var(--space-xs); min-width: 0; }
  .tool-name strong { font-family: var(--font-display); font-weight: 600; font-size: var(--text-lg); color: var(--text-strong); }
  .tool-sub { display: inline-flex; font-size: var(--text-sm); color: var(--muted); }
  .tool-sub > * + * { margin-left: var(--space-xs); padding-left: var(--space-xs); box-shadow: inset 1px 0 0 var(--border-strong); }
  .tool-meta { display: flex; flex-wrap: wrap; gap: var(--space-2xs) var(--space-sm); align-items: center; margin-top: var(--space-xs); }
  .detail { font-size: var(--text-sm); color: var(--muted); }
  .detail .mono { color: var(--text-strong); }
  .note { display: flex; gap: var(--space-xs); align-items: flex-start; margin: var(--space-xs) 0 0; font-size: var(--text-sm); color: var(--muted); }
  .note :global(svg) { margin-top: var(--space-3xs); }
  .note.bad { color: var(--bad); }
  .note.warn { color: var(--warn); }
  .planned { padding: var(--space-sm) var(--space-md); }
  .planned summary { cursor: pointer; color: var(--muted); font-size: var(--text-sm); }
  .planned p { margin: var(--space-xs) 0 0; }
  .facts { padding: var(--space-md); }
  .facts.posture { border-top: var(--rule-hair) solid var(--border); background: var(--color-paper); }
  .facts.posture dd { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-xs); }
  .load { display: flex; gap: var(--space-sm); }
  .reports { list-style: none; margin: 0; padding: 0; border-top: var(--rule-hair) solid var(--border); }
  .reports > li { padding: var(--space-sm) 0; border-bottom: var(--rule-hair) solid var(--border); }
  .changes { margin: var(--space-xs) 0 0; padding-left: var(--space-md); }
  .err { margin-top: var(--space-xs); color: var(--color-graphite-error); }
  .layers { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-xs); margin-bottom: var(--space-sm); }
  .layers ol { display: flex; flex-wrap: wrap; gap: var(--space-2xs); margin: 0; padding: 0; list-style: none; counter-reset: layer; }
  .layers li { counter-increment: layer; display: inline-flex; align-items: center; gap: var(--space-2xs); }
  .layers li::before { content: counter(layer); font-family: var(--font-display); font-weight: 600; font-size: var(--text-xs); color: var(--muted); }
  .layers li + li { padding-left: var(--space-xs); box-shadow: inset 1px 0 0 var(--border-strong); }
  .doc-head { display: flex; justify-content: space-between; gap: var(--space-sm); padding: var(--space-xs) var(--space-md); background: var(--color-graphite-2); color: var(--color-graphite-muted); border-radius: var(--radius-input) var(--radius-input) 0 0; }
  .doc .yaml { max-height: 560px; border-top-left-radius: 0; border-top-right-radius: 0; }
  @supports (corner-shape: bevel) {
    .doc-head { border-radius: var(--cut) 2px 0 0; corner-shape: bevel round; }
    .doc .yaml { border-radius: 0 0 var(--cut) 2px; corner-shape: bevel round; }
  }
  @media (max-width: 1100px) { .overview-grid, .policy-grid { grid-template-columns: minmax(0, 1fr); } }
</style>
