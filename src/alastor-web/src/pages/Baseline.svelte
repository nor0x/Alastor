<script lang="ts">
  import { parseDocument } from 'yaml';
  import { api, errorText, type PolicyLayerDetail } from '../lib/api';
  import {
    categoryLabels, commandGroups, ignorePath, scoreTone, setLayerKey, severityHelp, severityRank, weightsText,
    type BaselineCheck, type BaselineFleet, type BaselineFleetCheck, type ScopeOption,
  } from '../lib/baseline';
  import { fleet } from '../lib/fleet.svelte';
  import { refreshOn } from '../lib/live.svelte';
  import { route } from '../lib/router.svelte';
  import { canWrite } from '../lib/session.svelte';
  import { toast } from '../lib/toast.svelte';
  import { confirm } from '../lib/ui/confirm.svelte';
  import ApplyFixDialog from '../lib/ApplyFixDialog.svelte';
  import FixCommands from '../lib/FixCommands.svelte';
  import FleetHardening from '../lib/FleetHardening.svelte';
  import FleetNetwork from '../lib/FleetNetwork.svelte';
  import Severity from '../lib/ui/Severity.svelte';
  import Time from '../lib/ui/Time.svelte';

  let data = $state<BaselineFleet | null>(null);
  let globalYaml = $state('');
  let error = $state('');
  const initialView = new URLSearchParams(route.search).get('view');
  let view = $state<'checks' | 'hosts' | 'lynis' | 'exposure'>(initialView === 'hosts' || initialView === 'lynis' || initialView === 'exposure' ? initialView : 'checks');
  let onlyFailing = $state(false);
  let fixFor = $state<BaselineFleetCheck | null>(null);
  let fixOpen = $state(false);

  async function load() {
    try {
      const [d, g] = await Promise.all([api<BaselineFleet>('/api/baseline'), api<PolicyLayerDetail>('/api/policies/global')]);
      data = d;
      globalYaml = g.yaml;
      error = '';
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    load();
    return refreshOn(['baselineUpdated', 'policyChanged'], load, 30_000);
  });

  $effect(() => {
    history.replaceState(null, '', view === 'checks' ? '/baseline' : `/baseline?view=${view}`);
  });

  /** What the global layer sets for a check: "apply", "ignore", true (sshd jail), or undefined. */
  const globalDoc = $derived(parseDocument(globalYaml || '{}'));
  const globalValue = (c: BaselineCheck, path = c.policyPath) => globalDoc.getIn(path) as unknown;
  const appliedFleetWide = (c: BaselineCheck) => c.fix === 'Policy' && String(globalValue(c)) === c.policyValue;
  const acceptedFleetWide = (c: BaselineCheck) => globalValue(c, ignorePath(c)) === 'ignore';

  const sorted = $derived(
    (data?.checks ?? [])
      .filter((c) => !onlyFailing || c.failing > 0)
      .slice()
      .sort((a, b) => Number(b.failing > 0) - Number(a.failing > 0) || severityRank[b.check.severity] - severityRank[a.check.severity] || b.failing - a.failing || a.check.title.localeCompare(b.check.title)),
  );
  const failingChecks = $derived(data?.checks.filter((c) => c.failing > 0).length ?? 0);
  const hostsSorted = $derived((data?.hosts ?? []).slice().sort((a, b) => (a.score ?? 101) - (b.score ?? 101) || a.name.localeCompare(b.name)));

  const scopes = $derived<ScopeOption[]>([
    { key: 'global', layer: { scope: 'global' }, label: 'All hosts', help: 'The global policy. Groups and hosts can still opt out.' },
    ...fleet.groups.map((g) => ({ key: g.id, layer: { scope: 'group', id: g.id }, label: `Group ${g.name}`, help: `${g.hostCount} host${g.hostCount === 1 ? '' : 's'}.` }) as ScopeOption),
  ]);

  function openFix(fc: BaselineFleetCheck) {
    fixFor = fc;
    fixOpen = true;
  }

  async function acceptAll(c: BaselineCheck) {
    const ok = await confirm(`Accept "${c.title}" on all hosts?`,
      'The check keeps running everywhere, but no longer lowers scores or raises alerts. A group or host can still opt back in.',
      { confirmLabel: 'Accept risk' });
    if (!ok) return;
    try {
      await setLayerKey({ scope: 'global' }, ignorePath(c), 'ignore', `Baseline: accept risk "${c.title}" fleet-wide`);
      toast('Accepted on all hosts.');
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  async function clearGlobal(c: BaselineCheck, what: 'fix' | 'accept') {
    if (what === 'fix') {
      const ok = await confirm(`Remove the fleet-wide fix for "${c.title}"?`,
        'Agents delete the setting they wrote and restore the previous value. Groups or hosts that apply it themselves keep it.',
        { confirmLabel: 'Remove fix', danger: true });
      if (!ok) return;
    }
    try {
      await setLayerKey({ scope: 'global' }, what === 'fix' ? c.policyPath : ignorePath(c), undefined, `Baseline: ${what === 'fix' ? 'remove fix' : 'stop accepting'} "${c.title}" fleet-wide`);
      toast(what === 'fix' ? 'Fleet-wide fix removed.' : 'No longer accepted fleet-wide.');
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  const reported = (c: BaselineFleetCheck) => c.passing + c.failing + c.accepted;
</script>

<div class="page-head">
  <div>
    <h1>Security baseline</h1>
    <p class="sub">The most common server hardening checks, run by every agent. Most fixes are one click: the agent applies them as files it manages and can undo.</p>
  </div>
  <div class="seg" role="group" aria-label="View">
    <button class:on={view === 'checks'} aria-pressed={view === 'checks'} onclick={() => (view = 'checks')}>By check</button>
    <button class:on={view === 'hosts'} aria-pressed={view === 'hosts'} onclick={() => (view = 'hosts')}>By host</button>
    <button class:on={view === 'lynis'} aria-pressed={view === 'lynis'} onclick={() => (view = 'lynis')}>Lynis audit</button>
    <button class:on={view === 'exposure'} aria-pressed={view === 'exposure'} onclick={() => (view = 'exposure')}>Exposure</button>
  </div>
</div>

{#if view === 'lynis'}
  <FleetHardening />
{:else if view === 'exposure'}
  <FleetNetwork />
{:else if error && !data}
  <div class="banner bad" role="alert"><p>Couldn't load the baseline: {error}</p></div>
{:else if !data}
  <div class="skeleton-block"></div>
{:else}
  <section class="summary card" aria-label="Baseline summary">
    <div class="ledger strip">
      <div class="stat">
        <span class="figure-label">Average score</span>
        <span class="figure-value {scoreTone(data.averageScore)}">{#if data.averageScore !== null}{data.averageScore}{:else}<span class="nil" aria-label="none"></span>{/if}<span class="figure-of">/ 100</span></span>
      </div>
      <div class="stat">
        <span class="figure-label">Hosts checked</span>
        <span class="figure-value">{data.hostsReported}<span class="figure-of">/ {data.hostsTotal}</span></span>
      </div>
      <div class="stat">
        <span class="figure-label">Checks failing somewhere</span>
        <span class="figure-value" class:bad={failingChecks > 0}>{failingChecks}<span class="figure-of">/ {data.checks.length}</span></span>
      </div>
      <p class="muted small explain">
        The score weighs failures by severity ({weightsText}). Accepted risks and checks that
        don't apply are left out. Agents check every hour by default; change it with <code>baseline.checkSchedule</code> in the <a href="/policies/global">policy</a>.
      </p>
    </div>
  </section>

  {#if data.hostsTotal === 0}
    <div class="empty empty-dashed">No hosts yet. <a href="/settings/enrollment">Enroll a server</a> and its baseline shows up here a few seconds after the agent starts.</div>
  {:else if view === 'checks'}
    <div class="filterbar">
      <label class="check-label"><input type="checkbox" bind:checked={onlyFailing} /> Only checks that fail on some host</label>
    </div>
    <section class="card">
      <div class="cols" aria-hidden="true">
        <span class="th">Check</span>
        <span class="th" title="How many hosts pass, fail, or have accepted the risk">Hosts</span>
        <span class="th" title="How much a failure lowers the score: {weightsText}">Severity</span>
      </div>
      {#each sorted as fc (fc.check.id)}
        {@const c = fc.check}
        {@const total = reported(fc)}
        {@const manual = commandGroups(fc)}
        <details class="row">
          <summary>
            <span class="check-title">
              <span class="name">{c.title}</span>
              <span class="meta muted small">
                <span>{categoryLabels[c.category]}</span>
                <span>{c.fix === 'Policy' ? 'agent can fix' : 'manual fix'}</span>
                {#if appliedFleetWide(c)}<span class="applied">fix applied fleet-wide</span>{/if}
                {#if acceptedFleetWide(c)}<span>accepted fleet-wide</span>{/if}
              </span>
            </span>
            <span class="dist" aria-label="{fc.failing} failing, {fc.passing} passing, {fc.accepted} accepted">
              {#if total > 0}
                <span class="bar" aria-hidden="true">
                  {#if fc.failing}<span class="seg-fail" style:flex-grow={fc.failing}></span>{/if}
                  {#if fc.accepted}<span class="seg-acc" style:flex-grow={fc.accepted}></span>{/if}
                  {#if fc.passing}<span class="seg-pass" style:flex-grow={fc.passing}></span>{/if}
                </span>
              {/if}
              <span class="nums">
                {#if fc.failing}<span class="fail-n"><b>{fc.failing}</b> failing</span>{/if}
                {#if fc.passing}<span><b>{fc.passing}</b> pass</span>{/if}
                {#if fc.accepted}<span><b>{fc.accepted}</b> accepted</span>{/if}
                {#if !total}<span class="muted">{fc.notApplicable ? 'n/a' : fc.unknown ? 'unknown' : 'not checked'}</span>{/if}
              </span>
            </span>
            <Severity value={c.severity} title={severityHelp(c.severity)} />
          </summary>
          <div class="body">
            <p>{c.why}</p>
            <dl class="kv">
              <dt>Expected</dt><dd class="mono small">{c.expected}</dd>
              <dt>Fix</dt><dd>{c.remediation}</dd>
              {#if fc.unknown || fc.notApplicable}<dt>Other</dt><dd class="meta muted small">{#if fc.unknown}<span>{`${fc.unknown} unknown`}</span>{/if}{#if fc.notApplicable}<span>{`${fc.notApplicable} not applicable`}</span>{/if}</dd>{/if}
            </dl>
            {#if fc.failingHosts.length}
              <div class="hosts">
                <span class="label">Failing on</span>
                <ul>
                  {#each fc.failingHosts as h (h.id)}
                    <li><a href="/hosts/{h.id}?tab=baseline">{h.name}</a> <span class="mono small muted">{h.actual}</span></li>
                  {/each}
                </ul>
              </div>
            {/if}
            {#if canWrite()}
              <div class="actions">
                {#if c.fix === 'Policy' && !appliedFleetWide(c)}
                  <button class="btn primary small" onclick={() => openFix(fc)}>Apply fix…</button>
                {:else if c.fix === 'Manual' && fc.failing && !manual.length}
                  <span class="muted small">The commands depend on each host (SSH port, users, distribution). Open a failing host to copy them.</span>
                {/if}
                {#if appliedFleetWide(c) && c.policyPath[0] === 'baseline'}
                  <button class="btn small danger" onclick={() => clearGlobal(c, 'fix')}>Remove fleet-wide fix</button>
                {/if}
                {#if acceptedFleetWide(c)}
                  <button class="btn small" onclick={() => clearGlobal(c, 'accept')}>Stop accepting fleet-wide</button>
                {:else if fc.failing && !appliedFleetWide(c)}
                  <button class="btn small" onclick={() => acceptAll(c)}>Accept risk on all hosts</button>
                {/if}
              </div>
            {/if}
            {#if manual.length}
              {#if c.fix === 'Manual'}
                <FixCommands groups={manual} />
              {:else}
                <details class="by-hand">
                  <summary>Or fix it by hand</summary>
                  <FixCommands groups={manual} />
                </details>
              {/if}
            {/if}
          </div>
        </details>
      {:else}
        <div class="empty">No check fails on any host.</div>
      {/each}
    </section>
  {:else}
    <section class="card table-wrap">
      <table class="table">
        <thead><tr><th>Host</th><th class="hide-sm">Group</th><th class="num" title="0–100. Failing checks are weighted by severity; accepted risks are left out">Score</th><th class="num" title="Failing checks, not counting accepted risks">Failing</th><th class="num hide-sm" title="Failing checks rated high or critical">High / critical</th><th title="When the agent last ran the checks">Checked</th></tr></thead>
        <tbody>
          {#each hostsSorted as h (h.id)}
            <tr>
              <td>
                <span class="dot" class:ok={h.isOnline} class:bad={!h.isOnline} title={h.isOnline ? 'Online' : 'Offline'}></span>
                <a href="/hosts/{h.id}?tab=baseline">{h.name}</a>
              </td>
              <td class="hide-sm">{#if h.groupName}<span class="pill tag">{h.groupName}</span>{:else}<span class="nil" aria-label="none"></span>{/if}</td>
              <td class="num">{#if h.score !== null}<span class="pill {scoreTone(h.score)}">{h.score}</span>{:else}<span class="nil" aria-label="none"></span>{/if}</td>
              <td class="num">{#if h.checkedAt}{h.failing}{:else}<span class="nil" aria-label="none"></span>{/if}</td>
              <td class="num hide-sm">{#if h.failingHighOrCritical}<span class="bad-text">{h.failingHighOrCritical}</span>{:else if h.checkedAt}<span class="muted">0</span>{:else}<span class="nil" aria-label="none"></span>{/if}</td>
              <td class="nowrap">{#if h.checkedAt}<Time iso={h.checkedAt} />{:else}<span class="muted">not yet</span>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  <ApplyFixDialog bind:open={fixOpen} check={fixFor?.check ?? null} {scopes} manual={fixFor ? commandGroups(fixFor) : []} />
{/if}

<style>
  .summary { margin-bottom: var(--space-md); }
  .strip { display: flex; flex-wrap: wrap; }
  .strip > .stat { flex: 0 0 auto; min-width: 176px; }
  .strip > .explain { display: block; flex: 1 1 320px; align-self: stretch; margin: 0; }
  .check-label { display: inline-flex; gap: var(--space-xs); align-items: center; color: var(--color-ink-2); font-size: var(--text-sm); cursor: pointer; }
  /* Column labels for the check rows: the same grid as a summary, styled like a table header. */
  .cols { display: grid; grid-template-columns: minmax(0, 1fr) minmax(160px, 260px) 96px; gap: var(--space-md); padding: var(--space-xs) var(--space-md); border-bottom: var(--rule-hair) solid var(--border-strong); }
  .cols .th { justify-self: start; font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--muted); white-space: nowrap; }
  .row { border-bottom: var(--rule-hair) solid var(--border); }
  .row:last-child { border-bottom: 0; }
  .row > summary { display: grid; grid-template-columns: minmax(0, 1fr) minmax(160px, 260px) 96px; align-items: center; gap: var(--space-md); min-height: 56px; padding: var(--space-xs) var(--space-md); cursor: pointer; list-style: none; }
  .row > summary::-webkit-details-marker { display: none; }
  .row > summary:hover { background: var(--color-paper-2); }
  .row > summary:focus-visible { outline-offset: -2px; }
  .row[open] > summary { background: var(--color-paper-2); }
  .row > summary:active { background: var(--color-paper-3); }
  .check-title { display: flex; flex-direction: column; gap: var(--space-3xs); min-width: 0; }
  .check-title .name { font-weight: 500; color: var(--text-strong); }
  .meta { display: flex; flex-wrap: wrap; gap: var(--space-3xs) var(--space-xs); }
  .meta > span + span { padding-left: var(--space-xs); border-left: var(--rule-hair) solid var(--color-rule-2); }
  .meta .applied { color: var(--ok); }
  .dist { display: flex; flex-direction: column; gap: var(--space-2xs); }
  .bar {
    display: flex; height: 10px; background: var(--color-paper-3);
    -webkit-mask: repeating-linear-gradient(90deg, var(--color-ink) 0 4px, transparent 4px 6px);
    mask: repeating-linear-gradient(90deg, var(--color-ink) 0 4px, transparent 4px 6px);
  }
  .bar span { min-width: 4px; }
  .seg-fail { background: var(--bad); }
  .seg-acc { background: var(--color-rule-2); }
  .seg-pass { background: color-mix(in oklab, var(--ok) 50%, var(--color-paper-3)); }
  .nums { display: flex; flex-wrap: wrap; gap: var(--space-sm); font-size: var(--text-xs); color: var(--muted); font-variant-numeric: tabular-nums; }
  .nums b { font-family: var(--font-display); font-weight: 600; font-size: var(--text-sm); color: var(--text-strong); }
  .fail-n, .fail-n b, .bad-text { color: var(--bad); }
  .body { display: flex; flex-direction: column; gap: var(--space-sm); padding: var(--space-sm) var(--space-md) var(--space-md); border-top: var(--rule-hair) solid var(--border); background: var(--color-paper-2); }
  .body p { margin: 0; max-width: 75ch; }
  .hosts { display: flex; flex-direction: column; gap: var(--space-2xs); }
  .hosts ul { margin: 0; padding-left: var(--space-md); columns: 2 260px; font-size: var(--text-sm); }
  .actions { display: flex; flex-wrap: wrap; gap: var(--space-xs); align-items: center; }
  .by-hand > summary { width: fit-content; cursor: pointer; font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--color-ink-2); }
  .by-hand > summary:hover { color: var(--text-strong); }
  .by-hand[open] > summary { margin-bottom: var(--space-xs); }
  td .dot { margin-right: var(--space-xs); }
  @media (max-width: 640px) {
    .cols { display: none; }
    .row > summary { grid-template-columns: minmax(0, 1fr) auto; }
    .dist { grid-column: 1 / -1; grid-row: 2; }
    .strip > .stat { flex: 1 1 50%; min-width: 0; }
    .strip > .stat .figure-value { font-size: var(--text-figure-s); }
  }
</style>
