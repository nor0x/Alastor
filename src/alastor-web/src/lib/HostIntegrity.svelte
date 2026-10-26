<script lang="ts">
  import { untrack } from 'svelte';
  import { api, errorText, type Command, type HostIntegrity } from './api';
  import { on, refreshOn } from './live.svelte';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
  import Icon from './ui/Icon.svelte';
  import Severity from './ui/Severity.svelte';
  import Time from './ui/Time.svelte';

  // AIDE (files compared with an accepted baseline) and rkhunter (rootkit checks), both opt-in and report-only.
  let { hostId, isOnline }: { hostId: string; isOnline: boolean } = $props();

  let data = $state<HostIntegrity | null>(null);
  let error = $state('');
  let showAll = $state(false);
  let showLow = $state(false);

  async function load() {
    try {
      data = await api<HostIntegrity>(`/api/hosts/${hostId}/integrity`);
      error = '';
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

  const aide = $derived(data?.aide ?? null);
  const changes = $derived(
    (aide?.report?.mode === 'check' ? aide.report.changes : []).slice().sort((a, b) => Number(b.critical) - Number(a.critical) || a.path.localeCompare(b.path)),
  );
  const rk = $derived(data?.rootkit ?? null);
  const openWarnings = $derived((rk?.warnings ?? []).filter((w) => !w.ignored && w.severity !== 'Low' && w.severity !== 'Info'));
  const otherWarnings = $derived((rk?.warnings ?? []).filter((w) => !openWarnings.includes(w)));
  const critical = $derived(changes.filter((c) => c.critical).length);
  const checked = $derived(aide?.report?.mode === 'check');

  async function run(action: string, label: string, confirmText?: string) {
    if (confirmText && !(await confirm(label, confirmText, { confirmLabel: label }))) return;
    try {
      await api<Command>(`/api/hosts/${hostId}/actions/${action}`, { method: 'POST' });
      toast(isOnline ? `${label} queued.` : `The host is offline; it runs when the agent reconnects.`);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }
</script>

{#if error && !data}
  <div class="banner bad" role="alert"><Icon name="error" /><p>Couldn't load integrity checks: {error}</p></div>
{:else if !data || !aide || !rk}
  <div class="skeleton-block"></div>
{:else}
  <div class="stack">
    {#if aide.report || rk.mode}
      <section class="card summary">
        <div class="lead">
          <span class="figure-label">Changed files</span>
          <span class="figure-value" class:bad={critical > 0} class:warn={critical === 0 && changes.length > 0} class:ok={checked && changes.length === 0}>
            {#if checked}{changes.length}{:else}<span class="nil" aria-label="not checked yet"></span>{/if}
          </span>
        </div>
        <div class="counts">
          {#if checked}<span class="pair"><strong class="n" class:bad={critical > 0}>{critical}</strong> in binaries, SSH or account files</span>{/if}
          {#if aide.report}<span class="pair"><strong class="n">{aide.report.entries.toLocaleString()}</strong> entries in the baseline</span>{/if}
          {#if rk.mode === 'check'}<span class="pair"><strong class="n" class:bad={openWarnings.length > 0}>{openWarnings.length}</strong> rootkit warning{openWarnings.length === 1 ? '' : 's'}</span>{/if}
        </div>
        <div class="meta">
          <span class="meta-facts">
            {#if aide.run.checkedAt}<span>AIDE <Time iso={aide.run.checkedAt} /></span>{/if}
            {#if rk.run.checkedAt}<span>rkhunter <Time iso={rk.run.checkedAt} /></span>{/if}
          </span>
          <span class="keys">
            {#if canWrite() && aide.run.tool.installed}<button class="btn small" onclick={() => run('check-integrity', 'Integrity check')}>Check files</button>{/if}
            {#if canWrite() && rk.run.tool.installed}<button class="btn small" onclick={() => run('scan-rootkits', 'Rootkit check')}>Check rootkits</button>{/if}
          </span>
        </div>
      </section>
    {/if}

    <section class="card">
      <header>
        <h2>File integrity (AIDE)</h2>
        <span class="hint">
          {#if aide.run.schedule.value === 'off'}off{:else}<code>{aide.run.schedule.value}</code>{/if}{aide.run.tool.version ? ` · AIDE ${aide.run.tool.version}` : ''}
        </span>
      </header>
      <div class="card-body stack-sm">
        {#if aide.run.lastSucceeded === false}<div class="banner bad"><Icon name="error" /><p><strong>The last run failed:</strong> <span class="mono small">{aide.run.lastError}</span></p></div>{/if}
        {#if aide.run.schedule.value === 'off' && !aide.report}
          <p class="muted">Off. AIDE records a baseline of system binaries, <code>/etc</code> and SSH keys, then reports every file added, removed or changed since.
            Turn it on with <code>integrity.checkSchedule</code> (e.g. <code>"0 4 * * *"</code>) in this host's <a href="/policies/host/{hostId}">policy</a>; the agent installs AIDE from the distribution and keeps its own config and database.</p>
        {:else if !aide.report}
          <p class="muted">No run yet. The first run records the baseline.</p>
        {:else if aide.report.mode !== 'check'}
          <p>Baseline {aide.report.mode === 'init' ? 'recorded' : 'accepted'}: {aide.report.entries} entries. The next check compares against it.</p>
        {:else if changes.length === 0}
          <p class="state"><span class="pill ok">unchanged</span> {aide.report.entries.toLocaleString()} entries match the baseline.</p>
        {:else}
          <p>
            <strong>{changes.length} change{changes.length === 1 ? '' : 's'}</strong> since the baseline{#if critical}, <span class="bad-text">{critical} in binaries, SSH or account files</span>{/if}.
            After an update or an admin's edit that's expected; anything else deserves a look before you accept.
          </p>
          <div class="table-wrap flush">
            <table class="table">
              <thead><tr><th>Path</th><th>Change</th><th class="hide-sm">What changed</th></tr></thead>
              <tbody>
                {#each changes.slice(0, showAll ? undefined : 25) as c (c.path)}
                  <tr>
                    <td><span class="mono path">{c.path}</span>{#if c.critical}<span class="pill bad crit">critical path</span>{/if}</td>
                    <td><span class="pill {c.change === 'changed' ? 'warn' : c.change === 'added' ? 'info' : 'muted'}">{c.change}</span></td>
                    <td class="hide-sm small muted">{c.attributes.join(', ') || c.flags}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          {#if changes.length > 25}<button class="btn ghost small" onclick={() => (showAll = !showAll)}>{showAll ? 'Show fewer' : `Show all ${changes.length}`}</button>{/if}
        {/if}
        {#if canWrite() && aide.run.tool.installed && !(aide.report || rk.mode)}
          <div class="actions"><button class="btn small" onclick={() => run('check-integrity', 'Integrity check')}>Check now</button></div>
        {:else if canWrite() && aide.run.tool.installed && changes.length}
          <div class="actions"><button class="btn small" onclick={() => run('accept-integrity', 'Accept changes', 'AIDE records the files as they are now as the new baseline. Only do this once every change above is explained.')}>Accept changes</button></div>
        {/if}
      </div>
    </section>

    <section class="card">
      <header>
        <h2>Rootkit check (rkhunter)</h2>
        <span class="hint">
          {#if rk.run.schedule.value === 'off'}off{:else}<code>{rk.run.schedule.value}</code>{/if}{rk.version ? ` · rkhunter ${rk.version}` : ''}
        </span>
      </header>
      <div class="card-body stack-sm">
        {#if rk.run.lastSucceeded === false}<div class="banner bad"><Icon name="error" /><p><strong>The last run failed:</strong> <span class="mono small">{rk.run.lastError}</span></p></div>{/if}
        {#if rk.run.schedule.value === 'off' && !rk.mode}
          <p class="muted">Off. rkhunter looks for known rootkit files, changed system binaries, hidden files and risky settings. Turn it on with <code>malware.rootkitSchedule</code> (e.g. <code>"0 4 * * 0"</code>). It never downloads updates from the internet.</p>
        {:else if !rk.mode}
          <p class="muted">No run yet. The first run records file properties, then checks.</p>
        {:else if rk.mode === 'accept'}
          <p>File properties re-recorded. The next check compares against them.</p>
        {:else}
          {#if openWarnings.length === 0}<p class="state"><span class="pill ok">no open warnings</span></p>{/if}
          <ul class="warnings">
            {#each [...openWarnings, ...(showLow ? otherWarnings : [])] as w, i (i)}
              <li class:dim={w.ignored || w.severity === 'Low'}>
                <Severity value={w.severity} />
                <div>
                  <strong>{w.title}</strong>{#if w.ignored} <span class="pill muted">ignored</span>{/if}
                  {#each w.details as d (d)}<div class="mono small muted">{d}</div>{/each}
                </div>
              </li>
            {/each}
          </ul>
          {#if otherWarnings.length}<button class="btn ghost small" onclick={() => (showLow = !showLow)}>{showLow ? 'Hide' : 'Show'} {otherWarnings.length} low or ignored</button>{/if}
          <p class="small muted">Known warnings: add a fragment of their text to <code>malware.rootkitIgnore</code>{#if rk.ignore.length} (now: <span class="mono">{rk.ignore.join(', ')}</span>){/if}.</p>
        {/if}
        {#if canWrite() && rk.run.tool.installed && !(aide.report || rk.mode)}
          <div class="actions"><button class="btn small" onclick={() => run('scan-rootkits', 'Rootkit check')}>Check now</button></div>
        {:else if canWrite() && rk.run.tool.installed && openWarnings.some((w) => w.title.includes('file properties'))}
          <div class="actions"><button class="btn small" onclick={() => run('accept-rootkits', 'Accept file properties', 'rkhunter records the current binaries as known good. Do this after an update replaced them, never to silence an unexplained change.')}>Accept file properties</button></div>
        {/if}
      </div>
    </section>
  </div>
{/if}

<style>
  /* The summary ledger, the same strip on every host tab: lead figure | counts | when + keys, parted by hairlines. */
  .summary { display: grid; grid-template-columns: minmax(200px, max-content) minmax(0, 1fr) minmax(0, max-content); overflow: hidden; }
  .summary > * { display: flex; flex-direction: column; justify-content: center; gap: var(--space-2xs); min-width: 0; padding: var(--space-md); }
  .summary > * + * { box-shadow: inset 1px 0 0 var(--border); }
  .lead .figure-value { display: inline-flex; align-items: baseline; }
  .lead .figure-value .nil { width: 24px; height: 2px; align-self: center; }
  .counts { flex-direction: row; flex-wrap: wrap; align-items: center; align-content: center; justify-content: flex-start; gap: var(--space-xs) var(--space-lg); color: var(--muted); }
  .pair { display: inline-flex; align-items: baseline; gap: var(--space-2xs); color: var(--muted); }
  .pair .n { font-family: var(--font-display); font-weight: 600; font-size: var(--text-lg); line-height: 1; color: var(--text-strong); font-variant-numeric: tabular-nums; }
  .pair .n.bad { color: var(--bad); }
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

  .stack-sm { display: flex; flex-direction: column; gap: var(--space-sm); }
  .stack-sm p { margin: 0; }
  .state { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-xs); }
  .actions { display: flex; gap: var(--space-xs); flex-wrap: wrap; }
  .bad-text { color: var(--bad); }
  /* The changes table runs edge to edge inside the padded card body. */
  .flush { margin: 0 calc(-1 * var(--space-md)); border-top: var(--rule-hair) solid var(--border); border-bottom: var(--rule-hair) solid var(--border); }
  .path { overflow-wrap: anywhere; }
  .crit { margin-left: var(--space-xs); }
  .warnings { list-style: none; margin: 0; padding: 0; border-top: var(--rule-hair) solid var(--border); }
  .warnings li { display: grid; grid-template-columns: 96px minmax(0, 1fr); gap: var(--space-sm); align-items: start; padding: var(--space-xs) 0; border-bottom: var(--rule-hair) solid var(--border); }
  .warnings li > div { display: flex; flex-direction: column; gap: var(--space-3xs); min-width: 0; overflow-wrap: anywhere; }
  .warnings strong { color: var(--text-strong); font-family: var(--font-display); font-weight: 500; }
  .warnings li.dim { opacity: 0.6; }
  @media (max-width: 640px) { .warnings li { grid-template-columns: minmax(0, 1fr); gap: var(--space-2xs); } }
</style>
