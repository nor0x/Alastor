<script lang="ts">
  import { api, errorText, type Command, type HostIntegrity } from './api';
  import { on, refreshOn } from './live.svelte';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
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
    load();
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
  <div class="banner bad" role="alert"><p>Couldn't load integrity checks: {error}</p></div>
{:else if !data || !aide || !rk}
  <div class="skeleton-block"></div>
{:else}
  <div class="stack">
    <section class="card">
      <header>
        <h2>File integrity (AIDE)</h2>
        <span class="hint">
          {#if aide.run.schedule.value === 'off'}off{:else}<code>{aide.run.schedule.value}</code>{/if}
          {#if aide.run.checkedAt} · checked <Time iso={aide.run.checkedAt} />{/if}
          {#if aide.run.tool.version} · AIDE {aide.run.tool.version}{/if}
        </span>
      </header>
      <div class="card-body stack-sm">
        {#if aide.run.lastSucceeded === false}<div class="banner bad"><p><strong>The last run failed:</strong> <span class="mono small">{aide.run.lastError}</span></p></div>{/if}
        {#if aide.run.schedule.value === 'off' && !aide.report}
          <p class="muted">Off. AIDE records a baseline of system binaries, <code>/etc</code> and SSH keys, then reports every file added, removed or changed since.
            Turn it on with <code>integrity.checkSchedule</code> (e.g. <code>"0 4 * * *"</code>) in this host's <a href="/policies/host/{hostId}">policy</a>; the agent installs AIDE from the distribution and keeps its own config and database.</p>
        {:else if !aide.report}
          <p class="muted">No run yet. The first run records the baseline.</p>
        {:else if aide.report.mode !== 'check'}
          <p>Baseline {aide.report.mode === 'init' ? 'recorded' : 'accepted'}: {aide.report.entries} entries. The next check compares against it.</p>
        {:else if changes.length === 0}
          <p><span class="pill ok">✓ unchanged</span> {aide.report.entries} entries match the baseline.</p>
        {:else}
          <p>
            <strong>{changes.length} change{changes.length === 1 ? '' : 's'}</strong> since the baseline{#if changes.some((c) => c.critical)}, <span class="bad-text">{changes.filter((c) => c.critical).length} in binaries, SSH or account files</span>{/if}.
            After an update or an admin's edit that's expected; anything else deserves a look before you accept.
          </p>
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Path</th><th>Change</th><th class="hide-sm">What changed</th></tr></thead>
              <tbody>
                {#each changes.slice(0, showAll ? undefined : 25) as c (c.path)}
                  <tr>
                    <td class="mono small">{c.path}{#if c.critical}<span class="pill warn crit">critical</span>{/if}</td>
                    <td><span class="pill {c.change === 'changed' ? 'warn' : c.change === 'added' ? 'info' : 'muted'}">{c.change}</span></td>
                    <td class="hide-sm small muted">{c.attributes.join(', ') || c.flags}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          {#if changes.length > 25}<button class="btn ghost small" onclick={() => (showAll = !showAll)}>{showAll ? 'Show fewer' : `Show all ${changes.length}`}</button>{/if}
        {/if}
        {#if canWrite() && aide.run.tool.installed}
          <div class="actions">
            <button class="btn small" onclick={() => run('check-integrity', 'Integrity check')}>Check now</button>
            {#if changes.length}<button class="btn small" onclick={() => run('accept-integrity', 'Accept changes', 'AIDE records the files as they are now as the new baseline. Only do this once every change above is explained.')}>Accept changes</button>{/if}
          </div>
        {/if}
      </div>
    </section>

    <section class="card">
      <header>
        <h2>Rootkit check (rkhunter)</h2>
        <span class="hint">
          {#if rk.run.schedule.value === 'off'}off{:else}<code>{rk.run.schedule.value}</code>{/if}
          {#if rk.run.checkedAt} · checked <Time iso={rk.run.checkedAt} />{/if}
          {#if rk.version} · rkhunter {rk.version}{/if}
        </span>
      </header>
      <div class="card-body stack-sm">
        {#if rk.run.lastSucceeded === false}<div class="banner bad"><p><strong>The last run failed:</strong> <span class="mono small">{rk.run.lastError}</span></p></div>{/if}
        {#if rk.run.schedule.value === 'off' && !rk.mode}
          <p class="muted">Off. rkhunter looks for known rootkit files, changed system binaries, hidden files and risky settings. Turn it on with <code>malware.rootkitSchedule</code> (e.g. <code>"0 4 * * 0"</code>). It never downloads updates from the internet.</p>
        {:else if !rk.mode}
          <p class="muted">No run yet. The first run records file properties, then checks.</p>
        {:else if rk.mode === 'accept'}
          <p>File properties re-recorded. The next check compares against them.</p>
        {:else}
          {#if openWarnings.length === 0}<p><span class="pill ok">✓ no open warnings</span></p>{/if}
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
        {#if canWrite() && rk.run.tool.installed}
          <div class="actions">
            <button class="btn small" onclick={() => run('scan-rootkits', 'Rootkit check')}>Check now</button>
            {#if openWarnings.some((w) => w.title.includes('file properties'))}<button class="btn small" onclick={() => run('accept-rootkits', 'Accept file properties', 'rkhunter records the current binaries as known good. Do this after an update replaced them, never to silence an unexplained change.')}>Accept file properties</button>{/if}
          </div>
        {/if}
      </div>
    </section>
  </div>
{/if}

<style>
  .stack-sm { display: flex; flex-direction: column; gap: 10px; }
  .stack-sm p { margin: 0; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; }
  .bad-text { color: var(--bad); }
  .crit { margin-left: 8px; }
  .warnings { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
  .warnings li { display: grid; grid-template-columns: 84px 1fr; gap: 12px; align-items: start; }
  .warnings li.dim { opacity: 0.6; }
  @media (max-width: 640px) { .warnings li { grid-template-columns: 1fr; gap: 4px; } }
</style>
