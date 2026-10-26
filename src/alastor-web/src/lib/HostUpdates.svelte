<script lang="ts">
  import { untrack } from 'svelte';
  import CopyButton from './ui/CopyButton.svelte';
  import { api, errorText, type Command, type HostUpdates, type PendingUpdate } from './api';
  import { setLayerKey } from './baseline';
  import { on, refreshOn } from './live.svelte';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
  import Icon from './ui/Icon.svelte';
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
    // load() reads `data` before its first await; untracked, so a response doesn't re-run this effect.
    untrack(load);
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
      <div class="lead">
        <span class="figure-label">{unknownSecurity ? 'Pending updates' : 'Security updates'}</span>
        <span class="figure-value" class:bad={!!report && (report.security ?? report.pending) > 0}>{#if report}{report.security ?? report.pending}{:else}<span class="nil" aria-label="none"></span>{/if}</span>
      </div>
      <div class="counts">
        {#if report}
          <span class="pair"><strong class="n">{report.pending}</strong> pending in total</span>
          <span class="pair">via <code>{report.manager}</code></span>
          {#if report.rebootRequired}<span class="pill warn" title={report.rebootPackages.join(', ')}>reboot required</span>{/if}
        {/if}
      </div>
      <div class="meta">
        <span class="meta-facts">{#if data.checkedAt}<span>Checked <Time iso={data.checkedAt} /></span>{:else}<span>Not checked yet</span>{/if}</span>
        <span class="keys">
          {#if canWrite()}
            <button class="btn small" onclick={() => run('check')} disabled={!!busy}>{busy === 'check' ? 'Checking…' : 'Check now'}</button>
            <button class="btn small primary" onclick={() => run('apply')} disabled={!!busy || !report || (report.security ?? report.pending) === 0}>
              {busy === 'apply' ? 'Installing…' : unknownSecurity ? 'Install updates now' : 'Install security updates now'}
            </button>
          {/if}
        </span>
      </div>
    </section>

    {#if data.lastCheckSucceeded === false}
      <div class="banner bad" role="alert">
        <Icon name="error" />
        <p><strong>The last check failed:</strong> <span class="mono small">{data.lastCheckError}</span>{report ? ' The list below is from the last successful check.' : ''}</p>
      </div>
    {/if}

    {#if report?.rebootRequired}
      <div class="banner warn">
        <Icon name="alert" />
        <p>
          <strong>This host needs a reboot</strong> to finish installing{report.rebootPackages.length ? `: ${report.rebootPackages.join(', ')}` : ' updates'}.
          Until then the old kernel or libraries keep running. Alastor never reboots hosts; schedule a reboot when it suits you.
          {#if report.expectedKernel}Running kernel <span class="mono">{report.runningKernel}</span>, installed <span class="mono">{report.expectedKernel}</span>.{/if}
        </p>
      </div>
    {/if}

    {#if report?.restartServices?.length}
      {@const cmd = `sudo systemctl restart ${report.restartServices.join(' ')}`}
      <section class="card restart">
        <header><h2>Services to restart</h2><span class="hint">from {report.restartTool}</span></header>
        <div class="card-body">
          <p class="small">These services still run code from libraries or binaries that updates replaced, so the fixes aren't active in them yet. Restarting them is enough; no reboot needed for these.</p>
          <ul class="svc">{#each report.restartServices as s (s)}<li class="mono small">{s}</li>{/each}</ul>
          <div class="cmd"><code>{cmd}</code><CopyButton text={cmd} /></div>
          {#if report.restartServices.some((s) => s.startsWith('ssh'))}<p class="small muted">Restarting sshd keeps existing sessions open.</p>{/if}
        </div>
      </section>
    {:else if report && report.restartServices === null && report.manager !== 'apk'}
      <p class="small muted">Install <code>{report.manager === 'apt' ? 'needrestart' : 'dnf-utils'}</code> to see which services still run replaced code after updates. The agent only lists them; it never restarts anything.</p>
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
          <div class="empty">Everything is up to date.</div>
        {:else}
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Package</th><th class="hide-sm">Installed</th><th>Available</th><th class="hide-sm">From</th></tr></thead>
              <tbody>
                {#each visible as p (p.name)}
                  <tr>
                    <td>
                      <span class="pkg">
                        <span class="mono">{p.name}</span>
                        {#if p.security === true}<span class="pill bad">security</span>{/if}
                      </span>
                    </td>
                    <td class="mono small muted hide-sm">{#if p.installed}{p.installed}{:else}<span class="nil" aria-label="none"></span>{/if}</td>
                    <td class="mono small"><span class="avail"><span class="dot {tone(p)}" aria-hidden="true"></span>{p.candidate}</span></td>
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
              <details class="output">
                <summary>Package manager output</summary>
                <pre class="code-block log">{a.logTail}</pre>
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
            <label for="apply-sched" class="label">Schedule for this host</label>
            <input id="apply-sched" class="field mono" bind:value={scheduleDraft} placeholder={'off, every 12h or "0 4 * * *"'} />
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
  .restart .card-body { display: flex; flex-direction: column; gap: var(--space-sm); }
  .svc { margin: 0; padding-left: var(--space-lg); columns: 2; column-gap: var(--space-lg); }
  .svc li { padding: var(--space-3xs) 0; }
  @media (max-width: 640px) { .svc { columns: 1; } }
  /* The summary ledger, the same strip on every host tab: lead figure | counts | when + keys, parted by hairlines. */
  .summary { display: grid; grid-template-columns: minmax(200px, max-content) minmax(0, 1fr) minmax(0, max-content); overflow: hidden; }
  .summary > * { display: flex; flex-direction: column; justify-content: center; gap: var(--space-2xs); min-width: 0; padding: var(--space-md); }
  .summary > * + * { box-shadow: inset 1px 0 0 var(--border); }
  .lead .figure-value { display: inline-flex; align-items: baseline; }
  .lead .figure-value .nil { width: 24px; height: 2px; align-self: center; }
  .counts { flex-direction: row; flex-wrap: wrap; align-items: center; align-content: center; justify-content: flex-start; gap: var(--space-xs) var(--space-lg); color: var(--muted); }
  .pair { display: inline-flex; align-items: baseline; gap: var(--space-2xs); color: var(--muted); }
  .pair .n { font-family: var(--font-display); font-weight: 600; font-size: var(--text-lg); line-height: 1; color: var(--text-strong); font-variant-numeric: tabular-nums; }
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
  .pair code { font-size: var(--text-code); }

  .pad { padding: var(--space-md); }
  .stack-sm { display: flex; flex-direction: column; gap: var(--space-xs); }
  .stack-sm p { margin: 0; }
  .pkg, .avail { display: inline-flex; align-items: center; flex-wrap: wrap; gap: var(--space-xs); }
  .src { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .output > summary { width: fit-content; cursor: pointer; font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--color-ink-2); }
  .output > summary:hover { color: var(--text-strong); }
  .output[open] > summary { margin-bottom: var(--space-xs); }
  .log { max-height: 320px; }
  .sched { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-xs); }
  .sched .label { margin-right: var(--space-2xs); }
  .sched .field { flex: 1; min-width: 180px; max-width: 280px; font-size: var(--text-code); }
</style>
