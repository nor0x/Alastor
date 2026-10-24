<script lang="ts">
  import { api, errorText, type Command, type HostUpdates, type PendingUpdate } from './api';
  import { setLayerKey } from './baseline';
  import { on, refreshOn } from './live.svelte';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
  import Time from './ui/Time.svelte';

  let { hostId, isOnline }: { hostId: string; isOnline: boolean } = $props();

  let data = $state<HostUpdates | null>(null);
  let error = $state('');
  let busy = $state<'' | 'check' | 'apply'>('');
  let showAll = $state(false);
  let scheduleDraft = $state('');
  let savingSchedule = $state(false);

  async function load() {
    try {
      const prev = data?.checkedAt;
      data = await api<HostUpdates>(`/api/hosts/${hostId}/updates`);
      error = '';
      if (busy && data.checkedAt !== prev) busy = '';
      scheduleDraft = data.schedules.find((s) => s.key === 'updates.applySchedule')?.value ?? 'off';
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    void hostId;
    load();
    const offs = [
      on('hostUpdated', (h: { id: string }) => { if (h.id === hostId) load(); }),
      refreshOn(['policyChanged'], load, 60_000),
    ];
    return () => offs.forEach((o) => o());
  });

  const report = $derived(data?.report ?? null);
  const unknownSecurity = $derived(report !== null && report.security === null);
  const sorted = $derived(
    [...(report?.packages ?? [])].sort((a, b) => Number(b.security === true) - Number(a.security === true) || a.name.localeCompare(b.name)),
  );
  const security = $derived(sorted.filter((p) => p.security === true));
  const visible = $derived(showAll || sorted.length <= 15 ? sorted : sorted.slice(0, Math.max(15, security.length)));
  const schedule = (key: string) => data?.schedules.find((s) => s.key === key);
  const applySchedule = $derived(schedule('updates.applySchedule'));
  const autoApply = $derived(applySchedule !== undefined && applySchedule.value !== 'off');

  async function run(action: 'check' | 'apply') {
    if (action === 'apply') {
      const what = unknownSecurity ? 'all pending updates (Alpine can\'t tell security updates apart)' : 'the pending security updates';
      const ok = await confirm('Install updates now?',
        `The agent installs ${what} with the host's own package manager${report?.manager === 'apt' ? ' (unattended-upgrade, using its configured origins)' : ''}. Services may restart; the host is never rebooted.`,
        { confirmLabel: 'Install now' });
      if (!ok) return;
    }
    try {
      await api<Command>(`/api/hosts/${hostId}/actions/${action === 'check' ? 'check-updates' : 'apply-updates'}`, { method: 'POST' });
      busy = action;
      toast(!isOnline ? 'The host is offline; it runs this when the agent reconnects.'
        : action === 'check' ? 'Check queued. Refreshing the package lists can take a minute.' : 'Install queued. This page updates when the agent reports back.');
      setTimeout(() => (busy = ''), 15 * 60_000);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  async function saveSchedule(value: string | undefined) {
    savingSchedule = true;
    try {
      await setLayerKey({ scope: 'host', id: hostId }, ['updates', 'applySchedule'], value, value === undefined
        ? 'Updates: inherit the automatic install schedule' : `Updates: automatic installs "${value}"`);
      toast(value === undefined ? 'This host now inherits the schedule from its group or the global policy.' : 'Saved for this host.');
      await load();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      savingSchedule = false;
    }
  }

  const tone = (p: PendingUpdate) => (p.security === true ? 'bad' : p.security === null ? 'warn' : 'muted');
</script>

{#if error && !data}
  <div class="banner bad" role="alert"><p>Couldn't load updates: {error}</p></div>
{:else if !data}
  <div class="skeleton-block"></div>
{:else}
  <div class="stack">
    <section class="card summary">
      <div class="figure">
        <span class="big" class:bad-text={!!report && (report.security ?? report.pending) > 0}>{report ? (report.security ?? report.pending) : '—'}</span>
        <span class="muted small">{unknownSecurity ? 'pending updates' : 'security updates'}</span>
      </div>
      <div class="counts">
        {#if report}
          <span><strong class="n">{report.pending}</strong> pending in total</span>
          <span class="muted">via <code>{report.manager}</code></span>
          {#if report.rebootRequired}<span class="pill warn" title={report.rebootPackages.join(', ')}>reboot required</span>{/if}
        {/if}
      </div>
      <div class="meta">
        {#if data.checkedAt}<span class="muted small">Checked <Time iso={data.checkedAt} /></span>{:else}<span class="muted small">Not checked yet</span>{/if}
        {#if canWrite()}
          <button class="btn small" onclick={() => run('check')} disabled={!!busy}>{busy === 'check' ? 'Checking…' : 'Check now'}</button>
          <button class="btn small primary" onclick={() => run('apply')} disabled={!!busy || !report || (report.security ?? report.pending) === 0}>
            {busy === 'apply' ? 'Installing…' : unknownSecurity ? 'Install updates now' : 'Install security updates now'}
          </button>
        {/if}
      </div>
    </section>

    {#if data.lastCheckSucceeded === false}
      <div class="banner bad" role="alert">
        <p><strong>The last check failed:</strong> <span class="mono small">{data.lastCheckError}</span>{report ? ' The list below is from the last successful check.' : ''}</p>
      </div>
    {/if}

    {#if report?.rebootRequired}
      <div class="banner warn">
        <p>
          <strong>This host needs a reboot</strong> to finish installing{report.rebootPackages.length ? `: ${report.rebootPackages.join(', ')}` : ' updates'}.
          Until then the old kernel or libraries keep running. SentinelVPS never reboots hosts; schedule a reboot when it suits you.
        </p>
      </div>
    {/if}

    {#if !report}
      <div class="empty empty-dashed">
        This host hasn't reported updates yet. Agents check on startup and then on <code>updates.checkSchedule</code> ({schedule('updates.checkSchedule')?.value ?? 'every 6h'}).
        If the agent is older than this server, update it first.
      </div>
    {:else}
      <section class="card">
        <header>
          <h2>Pending packages</h2>
          <span class="hint">{report.pending ? (unknownSecurity ? 'Alpine doesn\'t mark security updates' : 'security updates first') : ''}</span>
        </header>
        {#if report.pending === 0}
          <div class="empty">Everything is up to date. 🎉</div>
        {:else}
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Package</th><th class="hide-sm">Installed</th><th>Available</th><th class="hide-sm">From</th></tr></thead>
              <tbody>
                {#each visible as p (p.name)}
                  <tr>
                    <td>
                      <span class="mono">{p.name}</span>
                      {#if p.security === true}<span class="pill bad">security</span>{/if}
                    </td>
                    <td class="mono small muted hide-sm">{p.installed ?? '—'}</td>
                    <td class="mono small"><span class="dot {tone(p)}" aria-hidden="true"></span>{p.candidate}</td>
                    <td class="small muted hide-sm src">{p.source ?? ''}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          {#if visible.length < sorted.length}
            <div class="more"><button class="btn ghost small" onclick={() => (showAll = true)}>Show all {sorted.length}</button></div>
          {/if}
        {/if}
      </section>

      {#if report.lastApply}
        {@const a = report.lastApply}
        <section class="card">
          <header>
            <h2>Last install</h2>
            <span class="hint"><Time iso={a.atUtc} /></span>
          </header>
          <div class="pad stack-sm">
            {#if a.success}
              <p><span class="pill ok">succeeded</span> {a.upgraded.length ? `${a.upgraded.length} package${a.upgraded.length === 1 ? '' : 's'} upgraded: ` : 'Nothing needed installing.'}<span class="mono small">{a.upgraded.join(', ')}</span></p>
            {:else}
              <p><span class="pill bad">failed</span> <span class="mono small">{a.error}</span></p>
            {/if}
            {#if a.logTail}
              <details>
                <summary class="muted small">Package manager output</summary>
                <pre class="log">{a.logTail}</pre>
              </details>
            {/if}
          </div>
        </section>
      {/if}
    {/if}

    <section class="card">
      <header><h2>Automatic installs</h2><span class="hint">{autoApply ? 'on' : 'off'}</span></header>
      <div class="pad stack-sm">
        <p class="muted small">
          {#if autoApply}
            The agent installs security updates on <code>{applySchedule?.value}</code>{applySchedule?.isDefault ? ' (inherited)' : ''}, with the host's own package manager.
          {:else}
            Off: the agent only reports pending updates, and you install them with the button above.
          {/if}
          Checks run on <code>{schedule('updates.checkSchedule')?.value}</code>.
        </p>
        {#if canWrite()}
          <form class="sched" onsubmit={(e) => { e.preventDefault(); saveSchedule(scheduleDraft.trim() || 'off'); }}>
            <label for="apply-sched" class="small">Schedule for this host</label>
            <input id="apply-sched" class="mono" bind:value={scheduleDraft} placeholder={'off, every 12h or "0 4 * * *"'} />
            <button class="btn small" type="submit" disabled={savingSchedule}>Save</button>
            <button class="btn ghost small" type="button" disabled={savingSchedule} onclick={() => saveSchedule(undefined)}>Inherit</button>
          </form>
          <p class="muted small">Use <code>off</code>, an interval like <code>every 12h</code>, or a cron expression like <code>0 4 * * *</code> (host local time). Set it for many hosts in the group or global policy.</p>
        {/if}
      </div>
    </section>
  </div>
{/if}

<style>
  .summary { display: flex; flex-wrap: wrap; align-items: center; gap: 16px 32px; padding: 16px; }
  .figure { display: flex; flex-direction: column; min-width: 96px; }
  .figure .big { font-size: 34px; font-weight: 600; line-height: 1; font-variant-numeric: tabular-nums; color: var(--text-strong); }
  .figure .big.bad-text { color: var(--bad); }
  .counts { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 20px; color: var(--muted); }
  .counts .n { color: var(--text-strong); font-variant-numeric: tabular-nums; margin-right: 2px; }
  .meta { margin-left: auto; display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
  .pad { padding: 12px 16px 16px; }
  .stack-sm { display: flex; flex-direction: column; gap: 8px; }
  .stack-sm p { margin: 0; }
  td .pill { margin-left: 6px; }
  .src { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; vertical-align: 1px; background: var(--border); }
  .dot.bad { background: var(--bad); }
  .dot.warn { background: var(--warn); }
  .more { padding: 8px 16px; border-top: 1px solid var(--border); }
  .log { max-height: 320px; overflow: auto; margin: 6px 0 0; padding: 8px 10px; border-radius: 6px; background: var(--surface-2); font-size: 12px; white-space: pre-wrap; overflow-wrap: anywhere; }
  .sched { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
  .sched input { flex: 1; min-width: 180px; max-width: 280px; }
  @media (max-width: 640px) {
    .meta { margin-left: 0; }
  }
</style>
