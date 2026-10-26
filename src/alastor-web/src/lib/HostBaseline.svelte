<script lang="ts">
  import { api, errorText, type Command } from './api';
  import {
    categoryLabels, ignorePath, resetOnHost, scoreTone, setLayerKey, severityHelp, severityRank,
    type BaselineCheck, type HostBaseline, type ScopeOption,
  } from './baseline';
  import { on, refreshOn } from './live.svelte';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
  import ApplyFixDialog from './ApplyFixDialog.svelte';
  import CopyButton from './ui/CopyButton.svelte';
  import Icon from './ui/Icon.svelte';
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
      <span class="status s-{c.status?.toLowerCase()}" aria-hidden="true">
        {#if c.status === 'Pass'}<Icon name="check" />{:else if c.status === 'Fail'}<Icon name="error" />{:else if c.status === 'Unknown'}<Icon name="alert" />{:else}<span class="nil"></span>{/if}
      </span>
      <span class="name">
        <strong>{c.title}</strong>
        <span class="muted small mono actual">{c.actual ?? ''}</span>
      </span>
      <span class="badges">
        {#if c.enforced}<span class="pill info" title="The policy applies this fix on this host">fix applied</span>{/if}
        {#if c.accepted}<span class="pill muted">accepted risk</span>{/if}
        <span class="pill muted hide-sm">{categoryLabels[c.category]}</span>
        <Severity value={c.severity} title={severityHelp(c.severity)} />
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
      <div class="lead">
        <span class="figure-label">{data.score === null ? 'No score yet' : 'Baseline score'}</span>
        <span class="figure-value {scoreTone(data.score)}">{#if data.score !== null}{data.score}{:else}<span class="nil" aria-label="none"></span>{/if}</span>
      </div>
      <div class="counts">
        <span class="pair"><strong class="n" class:bad={failing.length > 0}>{failing.length}</strong> failing</span>
        <span class="pair"><strong class="n">{passing.length}</strong> passing</span>
        {#if accepted.length}<span class="pair"><strong class="n">{accepted.length}</strong> accepted</span>{/if}
        {#if unknown.length}<span class="pair"><strong class="n">{unknown.length}</strong> unknown</span>{/if}
        {#if notApplicable.length}<span class="pair"><strong class="n">{notApplicable.length}</strong> n/a</span>{/if}
      </div>
      <div class="meta">
        <span class="meta-facts">
          {#if data.checkedAt}<span>Checked <Time iso={data.checkedAt} /></span>{:else}<span>Not checked yet</span>{/if}
        </span>
        <span class="keys">{#if canWrite()}<button class="btn small" onclick={recheck} disabled={rechecking}>{rechecking ? 'Checking…' : 'Re-check now'}</button>{/if}</span>
      </div>
    </section>

    {#if data.checkedAt === null}
      <div class="empty empty-dashed">
        This host hasn't reported a baseline yet. Agents run it on startup and then on <code>baseline.checkSchedule</code> (every hour by default).
      </div>
    {:else}
      {#if canWrite() && policyFixable.length > 1}
        <div class="banner info">
          <Icon name="info" />
          <p>{policyFixable.length} failing checks can be fixed by the agent. Open a check and choose <strong>Apply fix</strong>, or fix them across the fleet from the <a href="/baseline">Baseline</a> page.</p>
        </div>
      {/if}

      <section class="card">
        <header><h2>Needs attention</h2><span class="hint">{failing.length ? 'most severe first' : ''}</span></header>
        {#if failing.length}
          <div class="list">{#each failing as c (c.id)}{@render checkRow(c, failing.length <= 3)}{/each}</div>
        {:else}
          <div class="empty">Every applicable check passes.</div>
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
  .keys .btn:disabled { cursor: not-allowed; }

  /* Check rows: hairline-separated, the body indents to the title. */
  .list { display: flex; flex-direction: column; }
  .check { border-bottom: var(--rule-hair) solid var(--border); }
  .check:last-child { border-bottom: 0; }
  .check > summary { display: flex; align-items: center; gap: var(--space-sm); min-height: 56px; padding: var(--space-xs) var(--space-md); cursor: pointer; list-style: none; }
  .check > summary::-webkit-details-marker { display: none; }
  .check > summary:hover { background: var(--color-paper-2); }
  .check > summary:active { background: var(--color-paper-3); }
  .check > summary:focus-visible { outline-offset: -2px; }
  .check[open] > summary { padding-bottom: var(--space-2xs); }
  .status { flex: none; display: inline-grid; place-items: center; width: 16px; height: 16px; }
  .s-pass { color: var(--ok); }
  .s-fail { color: var(--bad); }
  .s-unknown { color: var(--warn); }
  .s-notapplicable { color: var(--muted); }
  .name { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: var(--space-3xs); }
  .name strong { font-family: var(--font-display); font-weight: 500; color: var(--text-strong); }
  .actual { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .badges { display: flex; align-items: center; gap: var(--space-xs); flex: none; }
  .body { display: flex; flex-direction: column; gap: var(--space-sm); max-width: 96ch; padding: var(--space-xs) var(--space-md) var(--space-md) calc(var(--space-md) + 16px + var(--space-sm)); }
  .body p { margin: 0; }
  .body .kv { font-size: var(--text-sm); }
  .note { font-size: var(--text-sm); color: var(--warn); }
  /* The fix is a paper-2 well inside the panel, not a second box. */
  .fix { display: flex; flex-direction: column; gap: var(--space-sm); padding: var(--space-sm) var(--space-md); border-radius: var(--radius-input); background: var(--color-paper-2); }
  .row-actions { display: flex; gap: var(--space-xs); flex-wrap: wrap; }
  .commands { display: flex; flex-direction: column; gap: var(--space-xs); }
  .commands p { margin: 0; }
  .by-hand > summary { width: fit-content; cursor: pointer; font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--color-ink-2); }
  .by-hand > summary:hover { color: var(--text-strong); }
  .by-hand[open] > summary { margin-bottom: var(--space-xs); }
  @media (max-width: 640px) {
    .check > summary { flex-wrap: wrap; row-gap: var(--space-xs); }
    .badges { flex-basis: 100%; flex-wrap: wrap; padding-left: calc(16px + var(--space-sm)); }
    .body { padding-left: var(--space-md); }
  }
</style>
