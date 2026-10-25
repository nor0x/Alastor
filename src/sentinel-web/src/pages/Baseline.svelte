<script lang="ts">
  import { parseDocument } from 'yaml';
  import { api, errorText, type PolicyLayerDetail } from '../lib/api';
  import {
    categoryLabels, ignorePath, scoreTone, setLayerKey, severityRank,
    type BaselineCheck, type BaselineFleet, type BaselineFleetCheck, type ScopeOption,
  } from '../lib/baseline';
  import { fleet } from '../lib/fleet.svelte';
  import { refreshOn } from '../lib/live.svelte';
  import { route } from '../lib/router.svelte';
  import { canWrite } from '../lib/session.svelte';
  import { toast } from '../lib/toast.svelte';
  import { confirm } from '../lib/ui/confirm.svelte';
  import ApplyFixDialog from '../lib/ApplyFixDialog.svelte';
  import FleetHardening from '../lib/FleetHardening.svelte';
  import Severity from '../lib/ui/Severity.svelte';
  import Time from '../lib/ui/Time.svelte';

  let data = $state<BaselineFleet | null>(null);
  let globalYaml = $state('');
  let error = $state('');
  const initialView = new URLSearchParams(route.search).get('view');
  let view = $state<'checks' | 'hosts' | 'lynis'>(initialView === 'hosts' || initialView === 'lynis' ? initialView : 'checks');
  let onlyFailing = $state(false);
  let fixFor = $state<BaselineCheck | null>(null);
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

  function openFix(c: BaselineCheck) {
    fixFor = c;
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
  </div>
</div>

{#if view === 'lynis'}
  <FleetHardening />
{:else if error && !data}
  <div class="banner bad" role="alert"><p>Couldn't load the baseline: {error}</p></div>
{:else if !data}
  <div class="skeleton-block"></div>
{:else}
  <section class="summary card" aria-label="Baseline summary">
    <div class="stat">
      <span class="label">Average score</span>
      <span class="big {scoreTone(data.averageScore)}">{data.averageScore ?? '—'}<span class="of">/ 100</span></span>
    </div>
    <div class="stat">
      <span class="label">Hosts checked</span>
      <span class="big">{data.hostsReported}<span class="of">/ {data.hostsTotal}</span></span>
    </div>
    <div class="stat">
      <span class="label">Checks failing somewhere</span>
      <span class="big">{failingChecks}<span class="of">/ {data.checks.length}</span></span>
    </div>
    <p class="muted small explain">
      The score weighs failures by severity (critical 10, high 6, medium 3, low 1). Accepted risks and checks that
      don't apply are left out. Agents check every hour by default; change it with <code>baseline.checkSchedule</code> in the <a href="/policies/global">policy</a>.
    </p>
  </section>

  {#if data.hostsTotal === 0}
    <div class="empty empty-dashed">No hosts yet. <a href="/settings/enrollment">Enroll a server</a> and its baseline shows up here a few seconds after the agent starts.</div>
  {:else if view === 'checks'}
    <div class="filterbar">
      <label class="check-label"><input type="checkbox" bind:checked={onlyFailing} /> Only checks that fail on some host</label>
    </div>
    <section class="card">
      {#each sorted as fc (fc.check.id)}
        {@const c = fc.check}
        {@const total = reported(fc)}
        <details class="row">
          <summary>
            <span class="title">
              <strong>{c.title}</strong>
              <span class="muted small">{categoryLabels[c.category]} · {c.fix === 'Policy' ? 'agent can fix' : 'manual fix'}{appliedFleetWide(c) ? ' · fix applied fleet-wide' : ''}{acceptedFleetWide(c) ? ' · accepted fleet-wide' : ''}</span>
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
                {#if fc.failing}<span class="fail-n">{fc.failing} failing</span>{/if}
                {#if fc.passing}<span>{fc.passing} pass</span>{/if}
                {#if fc.accepted}<span>{fc.accepted} accepted</span>{/if}
                {#if !total}<span class="muted">{fc.notApplicable ? 'n/a' : fc.unknown ? 'unknown' : 'not checked'}</span>{/if}
              </span>
            </span>
            <Severity value={c.severity} />
          </summary>
          <div class="body">
            <p>{c.why}</p>
            <dl class="kv">
              <dt>Expected</dt><dd class="mono small">{c.expected}</dd>
              <dt>Fix</dt><dd>{c.remediation}</dd>
              {#if fc.unknown || fc.notApplicable}<dt>Other</dt><dd class="muted small">{fc.unknown ? `${fc.unknown} unknown` : ''}{fc.unknown && fc.notApplicable ? ' · ' : ''}{fc.notApplicable ? `${fc.notApplicable} not applicable` : ''}</dd>{/if}
            </dl>
            {#if fc.failingHosts.length}
              <div class="hosts">
                <span class="muted small">Failing on</span>
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
                  <button class="btn primary small" onclick={() => openFix(c)}>Apply fix…</button>
                {:else if c.fix === 'Manual' && fc.failing}
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
          </div>
        </details>
      {:else}
        <div class="empty">No check fails on any host. 🎉</div>
      {/each}
    </section>
  {:else}
    <section class="card table-wrap">
      <table class="table">
        <thead><tr><th>Host</th><th class="hide-sm">Group</th><th class="num">Score</th><th class="num">Failing</th><th class="num hide-sm">High / critical</th><th>Checked</th></tr></thead>
        <tbody>
          {#each hostsSorted as h (h.id)}
            <tr>
              <td>
                <span class="dot" class:ok={h.isOnline} class:bad={!h.isOnline} title={h.isOnline ? 'Online' : 'Offline'}></span>
                <a href="/hosts/{h.id}?tab=baseline">{h.name}</a>
              </td>
              <td class="hide-sm">{#if h.groupName}<span class="pill info">{h.groupName}</span>{:else}<span class="muted">—</span>{/if}</td>
              <td class="num">{#if h.score !== null}<span class="pill {scoreTone(h.score)}">{h.score}</span>{:else}<span class="muted">—</span>{/if}</td>
              <td class="num">{h.checkedAt ? h.failing : '—'}</td>
              <td class="num hide-sm">{#if h.failingHighOrCritical}<span class="bad-text">{h.failingHighOrCritical}</span>{:else}<span class="muted">{h.checkedAt ? 0 : '—'}</span>{/if}</td>
              <td class="nowrap">{#if h.checkedAt}<Time iso={h.checkedAt} />{:else}<span class="muted">not yet</span>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  <ApplyFixDialog bind:open={fixOpen} check={fixFor} {scopes} />
{/if}

<style>
  .summary { display: flex; flex-wrap: wrap; gap: 16px 40px; align-items: flex-end; padding: 16px; margin-bottom: 16px; }
  .stat { display: flex; flex-direction: column; gap: 4px; }
  .stat .label { color: var(--muted); font-size: 12px; }
  .stat .big { font-size: 28px; font-weight: 600; line-height: 1; font-variant-numeric: tabular-nums; color: var(--text-strong); }
  .stat .big.ok { color: var(--ok); }
  .stat .big.warn { color: var(--warn); }
  .stat .big.bad { color: var(--bad); }
  .of { font-size: 14px; color: var(--muted); font-weight: 400; margin-left: 4px; }
  .explain { flex: 1 1 320px; margin: 0; }
  .filterbar { display: flex; gap: 12px; margin-bottom: 12px; }
  .check-label { display: inline-flex; gap: 6px; align-items: center; color: var(--muted); font-size: 13px; }
  .row { border-bottom: 1px solid var(--border); }
  .row:last-child { border-bottom: 0; }
  .row > summary { display: grid; grid-template-columns: 1fr minmax(160px, 260px) 72px; align-items: center; gap: 16px; padding: 10px 16px; cursor: pointer; list-style: none; }
  .row > summary::-webkit-details-marker { display: none; }
  .row > summary:hover { background: var(--surface-2); }
  .title { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .dist { display: flex; flex-direction: column; gap: 4px; }
  .bar { display: flex; gap: 2px; height: 6px; }
  .bar span { border-radius: 3px; min-width: 4px; }
  .seg-fail { background: var(--bad); }
  .seg-acc { background: var(--muted); opacity: 0.6; }
  .seg-pass { background: var(--ok); }
  .nums { display: flex; gap: 10px; font-size: 12px; color: var(--muted); font-variant-numeric: tabular-nums; }
  .fail-n, .bad-text { color: var(--bad); }
  .body { padding: 4px 16px 16px; display: flex; flex-direction: column; gap: 10px; }
  .body p { margin: 0; }
  .kv { display: grid; grid-template-columns: max-content 1fr; gap: 4px 14px; margin: 0; font-size: 13px; }
  .kv dt { color: var(--muted); }
  .kv dd { margin: 0; }
  .hosts ul { margin: 4px 0 0; padding-left: 18px; columns: 2 260px; font-size: 13px; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  td .dot { margin-right: 6px; }
  @media (max-width: 640px) {
    .row > summary { grid-template-columns: 1fr auto; }
    .dist { grid-column: 1 / -1; grid-row: 2; }
  }
</style>
