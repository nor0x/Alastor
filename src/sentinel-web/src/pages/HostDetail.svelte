<script lang="ts">
  import { api, errorText, type Ban, type Command, type EventPage, type HostDetail, type MetricPoint, type SecurityEvent, type ToolStatus } from '../lib/api';
  import { fleet, refreshFleet } from '../lib/fleet.svelte';
  import { on, refreshOn } from '../lib/live.svelte';
  import { navigate, route } from '../lib/router.svelte';
  import { canWrite } from '../lib/session.svelte';
  import { toast } from '../lib/toast.svelte';
  import { bytes, fullDate, uptime } from '../lib/format';
  import { scoreTone } from '../lib/baseline';
  import { confirm } from '../lib/ui/confirm.svelte';
  import BanDialog from '../lib/BanDialog.svelte';
  import BanTable from '../lib/BanTable.svelte';
  import HostBaseline from '../lib/HostBaseline.svelte';
  import HostUpdates from '../lib/HostUpdates.svelte';
  import HostVulnerabilities from '../lib/HostVulnerabilities.svelte';
  import UpdatesBadge from '../lib/ui/UpdatesBadge.svelte';
  import VulnBadge from '../lib/ui/VulnBadge.svelte';
  import EventList from '../lib/ui/EventList.svelte';
  import MetricChart from '../lib/ui/MetricChart.svelte';
  import Modal from '../lib/ui/Modal.svelte';
  import Time from '../lib/ui/Time.svelte';

  let { id }: { id: string } = $props();

  type Tab = 'overview' | 'baseline' | 'updates' | 'vulnerabilities' | 'events' | 'bans' | 'policy' | 'commands';
  const tabs: [Tab, string][] = [['overview', 'Overview'], ['baseline', 'Baseline'], ['updates', 'Updates'], ['vulnerabilities', 'CVEs'], ['events', 'Events'], ['bans', 'Bans'], ['policy', 'Policy'], ['commands', 'Commands']];
  const tab = $derived((new URLSearchParams(route.search).get('tab') as Tab) || 'overview');

  let host = $state<HostDetail | null>(null);
  let notFound = $state(false);
  let error = $state('');
  let hours = $state(6);
  let metrics = $state<MetricPoint[]>([]);
  let events = $state<SecurityEvent[]>([]);
  let eventsNext = $state<string | null>(null);
  let bans = $state<Ban[]>([]);
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
    if (name === 'reclaim' && !(await confirm('Reclaim managed files?', 'Hand edits to files SentinelVPS manages on this host are overwritten with the policy. A backup is kept until the apply succeeds.', { confirmLabel: 'Reclaim', danger: true }))) return;
    try {
      const cmd = await api<Command>(`/api/hosts/${id}/actions/${name}`, { method: 'POST' });
      commands = [cmd, ...commands.filter((c) => c.id !== cmd.id)];
      toast(`${label} queued. ${host?.summary.isOnline ? 'The agent picks it up within seconds.' : 'The host is offline; it runs when the agent reconnects.'}`);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  async function remove() {
    if (!host) return;
    const ok = await confirm(
      `Remove ${host.summary.name}?`,
      'The agent secret is revoked immediately and the host disappears from the dashboard with its bans and metrics.\n\nOn the server itself, run "sudo sentinel-agent uninstall" to remove the agent and the configuration it manages.',
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
    if (t.availability === 'Disabled') return { tone: 'muted', label: t.optIn ? 'opt-in · off' : 'disabled' };
    if (t.availability === 'Unavailable') return { tone: 'bad', label: 'unavailable' };
    if (!t.installed) return { tone: 'warn', label: 'not installed' };
    if (!t.running) return { tone: 'bad', label: 'stopped' };
    return { tone: 'ok', label: 'running' };
  }
  const configHelp: Record<string, string> = {
    InSync: 'Configuration matches the policy.',
    Pending: 'The latest policy has not been applied yet.',
    Drifted: 'Someone edited a file SentinelVPS manages. It is left alone until you reclaim it.',
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
    This host doesn't exist (it may have been removed). <a href="/hosts">Back to hosts</a>
  </div>
{:else if error && !host}
  <div class="banner bad" role="alert"><p>Couldn't load the host: {error}</p></div>
{:else if !host}
  <div class="skeleton-block"></div>
{:else}
  {@const s = host.summary}
  <div class="crumbs"><a href="/hosts">Hosts</a> /</div>
  <div class="page-head">
    <div>
      <h1 class="title">
        {s.name}
        {#if s.isOnline}<span class="pill ok"><span class="dot ok"></span>online</span>
        {:else}<span class="pill bad"><span class="dot bad"></span>offline · last seen <Time iso={s.lastSeenAt} /></span>{/if}
      </h1>
      <p class="sub">
        {s.osPrettyName} · {s.architecture} · agent {s.agentVersion}
        {#if s.groupName} · group <span class="pill info">{s.groupName}</span>{/if}
        {#each s.tags as t (t)}<span class="pill muted tag">{t}</span>{/each}
      </p>
    </div>
    {#if canWrite()}
      <div class="actions">
        <button class="btn" onclick={() => action('reconcile', 'Re-apply policy')} title="Run the reconcile loop now">Re-apply policy</button>
        <button class="btn" onclick={() => action('refresh-bans', 'Ban list refresh')}>Refresh bans</button>
        <button class="btn" onclick={openEdit}>Edit</button>
        <button class="btn danger" onclick={remove}>Remove</button>
      </div>
    {/if}
  </div>

  {#if host.policyApplySuccess === false}
    <div class="banner bad spaced" role="alert">
      <p><strong>The last policy apply failed.</strong> The agent rolled back to the previous working config. See the Policy tab for the tool's error.</p>
    </div>
  {/if}
  {#if implemented.some((t) => t.configState === 'Drifted')}
    <div class="banner warn spaced">
      <p><strong>Managed config was edited by hand.</strong> SentinelVPS won't overwrite it until you reclaim it.</p>
      {#if canWrite()}<button class="btn small" onclick={() => action('reclaim', 'Reclaim')}>Reclaim</button>{/if}
    </div>
  {/if}

  <nav class="tabs" aria-label="Host sections">
    {#each tabs as [t, label] (t)}
      <button class:on={tab === t} aria-current={tab === t ? 'page' : undefined} onclick={() => setTab(t)}>
        {label}
        {#if t === 'baseline' && s.baselineFailing}<span class="count">{s.baselineFailing}</span>{/if}
        {#if t === 'updates' && (s.securityUpdates ?? s.pendingUpdates)}<span class="count">{s.securityUpdates ?? s.pendingUpdates}</span>{/if}
        {#if t === 'vulnerabilities' && (s.vulnCritical ?? 0) + (s.vulnHigh ?? 0) > 0}<span class="count">{(s.vulnCritical ?? 0) + (s.vulnHigh ?? 0)}</span>{/if}
        {#if t === 'bans' && bans.length}<span class="count">{bans.length}</span>{/if}
        {#if t === 'commands' && commands.some((c) => c.status === 'Pending' || c.status === 'Delivered')}<span class="count">…</span>{/if}
      </button>
    {/each}
  </nav>

  {#if tab === 'overview'}
    <div class="stack">
      <section class="card">
        <header>
          <h2>Live metrics</h2>
          <div class="seg" role="group" aria-label="Time range">
            {#each [[1, '1h'], [6, '6h'], [24, '24h'], [168, '7d']] as [h, label] (h)}
              <button class:on={hours === h} aria-pressed={hours === h} onclick={() => (hours = h as number)}>{label}</button>
            {/each}
          </div>
        </header>
        <div class="card-body charts">
          <MetricChart title="CPU" points={series('cpu')} max={100} />
          <MetricChart title="Memory · {bytes(host.memoryUsedBytes)} of {bytes(host.memoryTotalBytes)}" points={series('memory')} max={100} />
          <MetricChart title="Disk · {bytes(host.diskUsedBytes)} of {bytes(host.diskTotalBytes)}" points={series('disk')} max={100} />
          <MetricChart title="Load (1 min)" points={series('load1')} unit="" />
        </div>
      </section>

      <div class="grid-2">
        <section class="card">
          <header><h2>Capability matrix</h2><span class="hint">what the agent runs on this host</span></header>
          <ul class="tools">
            {#each implemented as t (t.toolId)}
              {@const st = toolState(t)}
              <li>
                <div class="tool-head">
                  <div>
                    <strong>{t.displayName}</strong>
                    <span class="muted small">· {t.capability}{t.version ? ` · v${t.version}` : ''}</span>
                  </div>
                  <span class="pill {st.tone}">{st.label}</span>
                </div>
                <div class="tool-meta">
                  {#if t.installed}
                    <span class="pill muted" title={t.ownership === 'Adopted' ? 'Was installed before SentinelVPS; the agent manages only its own files.' : 'Installed by SentinelVPS.'}>{t.ownership === 'Adopted' ? 'adopted existing install' : 'installed by SentinelVPS'}</span>
                    <span class="pill {configTone[t.configState]}" title={configHelp[t.configState]}>config: {t.configState === 'InSync' ? 'in sync' : t.configState.toLowerCase()}</span>
                  {/if}
                  {#each Object.entries(t.details) as [k, v] (k)}<span class="muted small">{k}: <span class="mono">{v}</span></span>{/each}
                </div>
                {#if t.unavailableReason && t.availability !== 'Available'}<p class="note">{t.unavailableReason}</p>{/if}
                {#if configHelp[t.configState] && t.configState !== 'InSync' && t.installed}<p class="note">{configHelp[t.configState]}</p>{/if}
                {#if t.lastError}<p class="note bad">⚠ {t.lastError}</p>{/if}
                {#each t.warnings as w (w)}<p class="note warn">⚠ {w}</p>{/each}
              </li>
            {/each}
          </ul>
          {#if planned.length}
            <details class="planned">
              <summary>{planned.length} more integrations planned</summary>
              <p class="muted small">{planned.map((t) => t.displayName).join(' · ')}</p>
            </details>
          {/if}
        </section>

        <section class="card">
          <header><h2>System</h2></header>
          <dl class="facts">
            <dt>Hostname</dt><dd class="mono">{s.hostname}</dd>
            <dt>IP addresses</dt><dd class="mono">{host.ipAddresses.join(', ') || '—'}</dd>
            <dt>OS</dt><dd>{s.osPrettyName} <span class="muted">({host.osId} {host.osVersion})</span></dd>
            <dt>Kernel</dt><dd class="mono">{host.kernelVersion}</dd>
            <dt>Uptime</dt><dd>{uptime(host.uptimeSeconds)}</dd>
            <dt>Load</dt><dd class="mono">{s.load1.toFixed(2)} · {host.load5.toFixed(2)} · {host.load15.toFixed(2)}</dd>
            <dt>Enrolled</dt><dd>{fullDate(host.enrolledAt)}</dd>
            <dt>Last heartbeat</dt><dd><Time iso={s.lastSeenAt} /></dd>
            <dt>Machine ID</dt><dd class="mono small">{host.machineId ?? '—'}</dd>
            <dt>Baseline</dt>
            <dd>
              {#if s.baselineScore !== null}
                <a href="/hosts/{id}?tab=baseline"><span class="pill {scoreTone(s.baselineScore)}">score {s.baselineScore}</span></a>
                {#if s.baselineFailing}<span class="muted small">{s.baselineFailing} failing</span>{/if}
              {:else}<span class="muted">not checked yet</span>{/if}
            </dd>
            <dt>Updates</dt>
            <dd>
              {#if s.pendingUpdates !== null}
                <a href="/hosts/{id}?tab=updates"><UpdatesBadge pending={s.pendingUpdates} security={s.securityUpdates} /></a>
                {#if s.rebootRequired}<span class="pill warn">reboot required</span>{/if}
              {:else}<span class="muted">not checked yet</span>{/if}
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
              {#if s.policySync === 'in-sync'}<span class="pill ok">✓ in sync</span>{:else if s.policySync === 'failed'}<span class="pill bad">✕ failed</span>{:else}<span class="pill info">… pending</span>{/if}
              <span class="mono small muted">rev {host.appliedRevision ?? '—'}</span>
            </dd>
          </dl>
        </section>
      </div>
    </div>
  {:else if tab === 'baseline'}
    <HostBaseline hostId={id} groupId={s.groupId} groupName={s.groupName} isOnline={s.isOnline} />
  {:else if tab === 'updates'}
    <HostUpdates hostId={id} isOnline={s.isOnline} />
  {:else if tab === 'vulnerabilities'}
    <HostVulnerabilities hostId={id} isOnline={s.isOnline} osId={host.osId} />
  {:else if tab === 'events'}
    <section class="card">
      <header><h2>Events</h2><a class="hint" href="/events?hostId={id}">Open in event timeline →</a></header>
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
    <div class="grid-2">
      <section class="card">
        <header>
          <h2>Last apply</h2>
          {#if host.policyAppliedAt}<span class="hint"><Time iso={host.policyAppliedAt} /></span>{/if}
        </header>
        <div class="card-body stack">
          <dl class="facts tight">
            <dt>Desired revision</dt><dd class="mono">{host.desiredRevision}</dd>
            <dt>Applied revision</dt><dd class="mono">{host.appliedRevision ?? '—'}</dd>
          </dl>
          {#if host.policyReport}
            {#each host.policyReport.tools as r (r.toolId)}
              <div class="report">
                <div class="tool-head">
                  <strong>{r.toolId}</strong>
                  <span class="pill {r.success ? configTone[r.state] : 'bad'}">{r.success ? (r.state === 'InSync' ? 'in sync' : r.state.toLowerCase()) : 'failed'}</span>
                </div>
                {#if r.error}<pre class="err">{r.error}</pre>{/if}
                {#if r.changes.length}<ul class="small">{#each r.changes as c (c)}<li>{c}</li>{/each}</ul>{:else}<p class="muted small">No changes needed.</p>{/if}
                {#each r.warnings as w (w)}<p class="note warn">⚠ {w}</p>{/each}
              </div>
            {/each}
          {:else}
            <p class="muted">The agent has not reported an apply yet.</p>
          {/if}
        </div>
      </section>
      <section class="card">
        <header>
          <h2>Effective policy</h2>
          <a class="hint" href="/policies/host/{id}">{canWrite() ? 'Edit host overrides →' : 'View host layer →'}</a>
        </header>
        <div class="card-body">
          {#if effective}
            <p class="muted small layers">
              Merged from:
              {#each effective.layers as l, i (l.layerId)}
                {i ? ' → ' : ''}<a href={l.scope === 'Global' ? '/policies/global' : `/policies/${l.scope.toLowerCase()}/${l.targetId}`}>{l.scope === 'Global' ? 'global' : l.scope === 'Group' ? `group ${s.groupName ?? ''}` : 'this host'} v{l.version}</a>
              {/each}
            </p>
            <pre class="yaml">{effective.yaml}</pre>
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
                <td><span class="mono">{c.type}</span> {#if c.payload.target}<span class="mono muted">{c.payload.target}</span>{/if}</td>
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
  .title { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .title .pill { font-size: 12px; font-weight: 400; }
  .tag { margin-left: 4px; }
  .spaced { margin-bottom: 12px; justify-content: space-between; align-items: center; }
  .seg { display: inline-flex; border: 1px solid var(--border-strong); border-radius: var(--radius); overflow: hidden; }
  .seg button { padding: 2px 10px; border: 0; background: var(--bg); color: var(--muted); cursor: pointer; font-size: 12px; }
  .seg button + button { border-left: 1px solid var(--border-strong); }
  .seg button.on { background: var(--surface-2); color: var(--text-strong); }
  .charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 220px), 1fr)); gap: 20px; }
  .tools { list-style: none; margin: 0; padding: 0; }
  .tools li { padding: 12px 16px; border-bottom: 1px solid var(--border); }
  .tool-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
  .tool-meta { display: flex; flex-wrap: wrap; gap: 6px 10px; align-items: center; margin-top: 6px; }
  .note { margin: 6px 0 0; font-size: 12.5px; color: var(--muted); }
  .note.bad { color: var(--bad); }
  .note.warn { color: var(--warn); }
  .planned { padding: 10px 16px; }
  .planned summary { cursor: pointer; color: var(--muted); font-size: 12.5px; }
  .planned p { margin: 6px 0 0; }
  .facts { display: grid; grid-template-columns: max-content 1fr; gap: 8px 16px; margin: 0; padding: 16px; font-size: 13px; }
  .facts.tight { padding: 0; }
  .facts dt { color: var(--muted); }
  .facts dd { margin: 0; overflow-wrap: anywhere; }
  .report { padding: 12px; border: 1px solid var(--border); border-radius: var(--radius); }
  .report ul { margin: 8px 0 0; padding-left: 18px; }
  .err { margin-top: 8px; padding: 8px; border-radius: 6px; background: var(--bad-bg); color: var(--bad); }
  .yaml { padding: 12px; border-radius: 6px; background: var(--bg); border: 1px solid var(--border); max-height: 520px; overflow: auto; }
  .layers { margin: 0 0 10px; }
  .more { padding: 12px; text-align: center; border-top: 1px solid var(--border); }
</style>
