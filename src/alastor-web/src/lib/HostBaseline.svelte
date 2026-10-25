<script lang="ts">
  import { api, errorText, type Command } from './api';
  import {
    categoryLabels, ignorePath, resetOnHost, scoreTone, setLayerKey, severityRank,
    type BaselineCheck, type HostBaseline, type ScopeOption,
  } from './baseline';
  import { on, refreshOn } from './live.svelte';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
  import ApplyFixDialog from './ApplyFixDialog.svelte';
  import CopyButton from './ui/CopyButton.svelte';
  import Severity from './ui/Severity.svelte';
  import Time from './ui/Time.svelte';

  let { hostId, groupId, groupName, isOnline }: { hostId: string; groupId: string | null; groupName: string | null; isOnline: boolean } = $props();

  let data = $state<HostBaseline | null>(null);
  let error = $state('');
  let rechecking = $state(false);
  let fixFor = $state<BaselineCheck | null>(null);
  let fixOpen = $state(false);
  let showPassing = $state(false);

  async function load() {
    try {
      data = await api<HostBaseline>(`/api/hosts/${hostId}/baseline`);
      error = '';
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    void hostId;
    load();
    const offs = [
      on('baselineUpdated', (id: string) => {
        if (id !== hostId) return;
        rechecking = false;
        load();
      }),
      refreshOn(['policyChanged'], load, 30_000),
    ];
    return () => offs.forEach((o) => o());
  });

  const bySeverity = (a: BaselineCheck, b: BaselineCheck) => severityRank[b.severity] - severityRank[a.severity] || a.title.localeCompare(b.title);
  const failing = $derived(data?.checks.filter((c) => c.status === 'Fail' && !c.accepted).sort(bySeverity) ?? []);
  const accepted = $derived(data?.checks.filter((c) => c.status === 'Fail' && c.accepted).sort(bySeverity) ?? []);
  const unknown = $derived(data?.checks.filter((c) => c.status === 'Unknown') ?? []);
  const passing = $derived(data?.checks.filter((c) => c.status === 'Pass').sort(bySeverity) ?? []);
  const notApplicable = $derived(data?.checks.filter((c) => c.status === 'NotApplicable') ?? []);
  const policyFixable = $derived(failing.filter((c) => c.fix === 'Policy' && !c.enforced));

  const scopes = $derived<ScopeOption[]>([
    { key: 'host', layer: { scope: 'host', id: hostId }, label: 'This host', help: 'Only this server. Safest way to try a fix first.' },
    ...(groupId ? [{ key: 'group', layer: { scope: 'group', id: groupId }, label: `Group ${groupName ?? ''}`.trim(), help: 'Every host in this group.' } as ScopeOption] : []),
    { key: 'global', layer: { scope: 'global' }, label: 'All hosts', help: 'The global policy. Groups and hosts can still opt out.' },
  ]);

  async function recheck() {
    try {
      await api<Command>(`/api/hosts/${hostId}/actions/recheck`, { method: 'POST' });
      rechecking = true;
      toast(isOnline ? 'Re-check queued. Results arrive within a few seconds.' : 'The host is offline; it re-checks when the agent reconnects.');
      setTimeout(() => (rechecking = false), 60_000);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  function openFix(c: BaselineCheck) {
    fixFor = c;
    fixOpen = true;
  }

  async function accept(c: BaselineCheck) {
    const ok = await confirm(`Accept the risk of "${c.title}"?`,
      'The check keeps running, but it no longer lowers this host\'s score or raises alerts. You can undo this at any time.',
      { confirmLabel: 'Accept risk' });
    if (!ok) return;
    try {
      await setLayerKey({ scope: 'host', id: hostId }, ignorePath(c), 'ignore', `Baseline: accept risk "${c.title}"`);
      toast('Accepted for this host.');
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  async function reset(c: BaselineCheck, what: string) {
    try {
      await resetOnHost(c, hostId, groupId, `Baseline: ${what} "${c.title}"`);
      toast(what === 'remove fix' ? 'Fix removed for this host. The agent deletes its setting and restores the previous value.' : 'This host reports the check again.');
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }
</script>

{#snippet checkRow(c: BaselineCheck, open: boolean)}
  <details class="check" {open}>
    <summary>
      <span class="status s-{c.status?.toLowerCase()}" aria-hidden="true">{c.status === 'Pass' ? '✓' : c.status === 'Fail' ? '✕' : c.status === 'Unknown' ? '?' : '–'}</span>
      <span class="name">
        <strong>{c.title}</strong>
        <span class="muted small mono actual">{c.actual ?? ''}</span>
      </span>
      <span class="badges">
        {#if c.enforced}<span class="pill info" title="The policy applies this fix on this host">fix applied</span>{/if}
        {#if c.accepted}<span class="pill muted">accepted risk</span>{/if}
        <span class="pill muted hide-sm">{categoryLabels[c.category]}</span>
        <Severity value={c.severity} />
      </span>
    </summary>
    <div class="body">
      <p>{c.why}</p>
      <dl class="kv">
        <dt>Expected</dt><dd class="mono small">{c.expected}</dd>
        <dt>On this host</dt><dd class="mono small">{c.actual ?? 'not checked yet'}</dd>
        {#if c.failingSince && c.status === 'Fail'}<dt>Failing since</dt><dd><Time iso={c.failingSince} /></dd>{/if}
      </dl>
      {#if c.detail}<p class="note">{c.detail}</p>{/if}

      {#if c.status === 'Fail' && c.fix === 'Policy' && !c.enforced}
        <div class="fix">
          <p><strong>Fix:</strong> {c.remediation}</p>
          {#if canWrite()}
            <div class="row-actions">
              <button class="btn primary small" onclick={() => openFix(c)}>Apply fix…</button>
              {#if !c.accepted}<button class="btn small" onclick={() => accept(c)}>Accept risk</button>{/if}
            </div>
          {/if}
          {#if c.commands.length}
            <details class="by-hand">
              <summary>Or fix it by hand</summary>
              {@render commandList(c.commands)}
            </details>
          {/if}
        </div>
      {:else if c.status === 'Fail' && (c.fix === 'Manual' || c.enforced)}
        <div class="fix">
          <p><strong>Fix:</strong> {c.remediation}</p>
          {#if c.commands.length}{@render commandList(c.commands)}{/if}
          {#if canWrite() && !c.accepted}
            <div class="row-actions"><button class="btn small" onclick={() => accept(c)}>Accept risk</button></div>
          {/if}
        </div>
      {/if}

      {#if canWrite() && (c.accepted || (c.enforced && c.policyPath[0] === 'baseline'))}
        <div class="row-actions">
          {#if c.accepted}<button class="btn small" onclick={() => reset(c, 'stop accepting')}>Stop accepting</button>{/if}
          {#if c.enforced && c.policyPath[0] === 'baseline'}<button class="btn small danger" onclick={() => reset(c, 'remove fix')}>Remove fix on this host</button>{/if}
        </div>
      {/if}
    </div>
  </details>
{/snippet}

{#snippet commandList(commands: string[])}
  <div class="commands">
    {#each commands as cmd, i (i)}
      <div class="cmd"><code>{cmd}</code><CopyButton text={cmd.replace(/\s+#.*$/, '')} /></div>
    {/each}
    <p class="muted small">Run on the host as an admin. Lines after <code>#</code> are notes and aren't copied.</p>
  </div>
{/snippet}

{#if error && !data}
  <div class="banner bad" role="alert"><p>Couldn't load the baseline: {error}</p></div>
{:else if !data}
  <div class="skeleton-block"></div>
{:else}
  <div class="stack">
    <section class="card summary">
      <div class="score {scoreTone(data.score)}">
        <span class="big">{data.score ?? '—'}</span>
        <span class="muted small">{data.score === null ? 'no score yet' : 'baseline score'}</span>
      </div>
      <div class="counts">
        <span><strong class="n bad-text">{failing.length}</strong> failing</span>
        <span><strong class="n">{passing.length}</strong> passing</span>
        {#if accepted.length}<span><strong class="n">{accepted.length}</strong> accepted</span>{/if}
        {#if unknown.length}<span><strong class="n">{unknown.length}</strong> unknown</span>{/if}
        {#if notApplicable.length}<span><strong class="n">{notApplicable.length}</strong> n/a</span>{/if}
      </div>
      <div class="meta">
        {#if data.checkedAt}<span class="muted small">Checked <Time iso={data.checkedAt} /></span>{:else}<span class="muted small">Not checked yet</span>{/if}
        {#if canWrite()}<button class="btn small" onclick={recheck} disabled={rechecking}>{rechecking ? 'Checking…' : 'Re-check now'}</button>{/if}
      </div>
    </section>

    {#if data.checkedAt === null}
      <div class="empty empty-dashed">
        This host hasn't reported a baseline yet. Agents run it on startup and then on <code>baseline.checkSchedule</code> (every hour by default).
      </div>
    {:else}
      {#if canWrite() && policyFixable.length > 1}
        <div class="banner info">
          <p>{policyFixable.length} failing checks can be fixed by the agent. Open a check and choose <strong>Apply fix</strong>, or fix them across the fleet from the <a href="/baseline">Baseline</a> page.</p>
        </div>
      {/if}

      <section class="card">
        <header><h2>Needs attention</h2><span class="hint">{failing.length ? 'most severe first' : ''}</span></header>
        {#if failing.length}
          <div class="list">{#each failing as c (c.id)}{@render checkRow(c, failing.length <= 3)}{/each}</div>
        {:else}
          <div class="empty">Every applicable check passes. 🎉</div>
        {/if}
      </section>

      {#if accepted.length || unknown.length}
        <section class="card">
          <header><h2>Accepted and unknown</h2></header>
          <div class="list">
            {#each accepted as c (c.id)}{@render checkRow(c, false)}{/each}
            {#each unknown as c (c.id)}{@render checkRow(c, false)}{/each}
          </div>
        </section>
      {/if}

      <section class="card">
        <header>
          <h2>Passing</h2>
          <button class="btn ghost small" onclick={() => (showPassing = !showPassing)} aria-expanded={showPassing}>{showPassing ? 'Hide' : `Show ${passing.length + notApplicable.length}`}</button>
        </header>
        {#if showPassing}
          <div class="list">
            {#each passing as c (c.id)}{@render checkRow(c, false)}{/each}
            {#each notApplicable as c (c.id)}{@render checkRow(c, false)}{/each}
          </div>
        {/if}
      </section>
    {/if}
  </div>

  <ApplyFixDialog bind:open={fixOpen} check={fixFor} {scopes} />
{/if}

<style>
  .summary { display: flex; flex-wrap: wrap; align-items: center; gap: 16px 32px; padding: 16px; }
  .score { display: flex; flex-direction: column; min-width: 96px; }
  .score .big { font-size: 34px; font-weight: 600; line-height: 1; font-variant-numeric: tabular-nums; color: var(--text-strong); }
  .score.ok .big { color: var(--ok); }
  .score.warn .big { color: var(--warn); }
  .score.bad .big { color: var(--bad); }
  .counts { display: flex; flex-wrap: wrap; gap: 6px 20px; color: var(--muted); }
  .counts .n { color: var(--text-strong); font-variant-numeric: tabular-nums; margin-right: 2px; }
  .counts .bad-text { color: var(--bad); }
  .meta { margin-left: auto; display: flex; align-items: center; gap: 12px; }
  .list { display: flex; flex-direction: column; }
  .check { border-bottom: 1px solid var(--border); }
  .check:last-child { border-bottom: 0; }
  .check > summary { display: flex; align-items: center; gap: 12px; padding: 10px 16px; cursor: pointer; list-style: none; }
  .check > summary::-webkit-details-marker { display: none; }
  .check > summary:hover { background: var(--surface-2); }
  .status { flex: none; width: 22px; height: 22px; border-radius: 50%; display: inline-grid; place-items: center; font-size: 12px; font-weight: 700; border: 1px solid currentColor; }
  .s-pass { color: var(--ok); }
  .s-fail { color: var(--bad); }
  .s-unknown { color: var(--warn); }
  .s-notapplicable { color: var(--muted); }
  .name { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
  .actual { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .badges { display: flex; align-items: center; gap: 6px; flex: none; }
  .body { padding: 4px 16px 14px 50px; display: flex; flex-direction: column; gap: 10px; }
  .body p { margin: 0; }
  .kv { display: grid; grid-template-columns: max-content 1fr; gap: 4px 14px; margin: 0; font-size: 13px; }
  .kv dt { color: var(--muted); }
  .kv dd { margin: 0; overflow-wrap: anywhere; }
  .note { font-size: 12.5px; color: var(--warn); }
  .fix { display: flex; flex-direction: column; gap: 8px; padding: 10px 12px; border-radius: var(--radius); background: var(--bg); border: 1px solid var(--border); }
  .row-actions { display: flex; gap: 8px; flex-wrap: wrap; }
  .commands { display: flex; flex-direction: column; gap: 6px; }
  .cmd { display: flex; align-items: flex-start; gap: 8px; }
  .cmd code { flex: 1; min-width: 0; padding: 6px 8px; border-radius: 6px; background: var(--surface-2); font-size: 12px; overflow-wrap: anywhere; white-space: pre-wrap; }
  .by-hand summary { cursor: pointer; color: var(--muted); font-size: 12.5px; margin-bottom: 6px; }
  @media (max-width: 640px) {
    .check > summary { flex-wrap: wrap; row-gap: 6px; }
    .badges { flex-basis: 100%; padding-left: 34px; }
    .body { padding-left: 16px; }
    .meta { margin-left: 0; }
  }
</style>
