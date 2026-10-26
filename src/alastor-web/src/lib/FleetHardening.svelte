<script lang="ts">
  import { api, errorText, lynisUrl, type FleetHardening } from './api';
  import { indexTone, lynisNotes } from './hardening';
  import { refreshOn } from './live.svelte';
  import Icon from './ui/Icon.svelte';
  import Time from './ui/Time.svelte';

  let data = $state<FleetHardening | null>(null);
  let error = $state('');

  async function load() {
    try {
      data = await api<FleetHardening>('/api/hardening');
      error = '';
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    load();
    return refreshOn(['hostUpdated', 'policyChanged'], load, 60_000);
  });

  const audited = $derived(data?.hosts.filter((h) => h.hardeningIndex !== null) ?? []);
  const hostsSorted = $derived((data?.hosts ?? []).slice().sort((a, b) => (a.hardeningIndex ?? 101) - (b.hardeningIndex ?? 101) || a.name.localeCompare(b.name)));
  const warnings = $derived(data?.items.filter((i) => i.kind === 'Warning') ?? []);
  const suggestions = $derived(data?.items.filter((i) => i.kind === 'Suggestion') ?? []);
</script>

{#if error && !data}
  <div class="banner bad" role="alert"><p>Couldn't load Lynis results: {error}</p></div>
{:else if !data}
  <div class="skeleton-block"></div>
{:else}
  <section class="summary card" aria-label="Lynis summary">
    <div class="ledger strip">
      <div class="stat">
        <span class="figure-label">Average hardening index</span>
        <span class="figure-value {indexTone(data.averageIndex)}">{#if data.averageIndex !== null}{data.averageIndex}{:else}<span class="nil" aria-label="none"></span>{/if}<span class="figure-of">/ 100</span></span>
      </div>
      <div class="stat">
        <span class="figure-label">Hosts audited</span>
        <span class="figure-value">{audited.length}<span class="figure-of">/ {data.hosts.length}</span></span>
      </div>
      <p class="muted small explain">
        <a href="https://cisofy.com/lynis/" target="_blank" rel="noreferrer">Lynis</a> runs a few hundred tests and scores the host. A fresh install
        usually scores 55 to 65. Treat the checklist as advice: accept what doesn't apply on each host's <strong>Hardening</strong> tab.
      </p>
    </div>
  </section>

  <section class="card">
    <header><h2>Hosts</h2><span class="hint">lowest index first</span></header>
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>Host</th><th title="Lynis hardening index, 0–100; higher is better">Index</th><th class="num" title="Findings Lynis rates worth fixing first">Warnings</th><th class="num hide-sm" title="Optional hardening advice">Suggestions</th><th class="hide-sm" title="When Lynis last ran">Audited</th></tr></thead>
        <tbody>
          {#each hostsSorted as h (h.hostId)}
            <tr>
              <td>
                <a href="/hosts/{h.hostId}?tab=hardening" class="name">{h.name}</a>
                {#if h.groupName}<span class="pill tag">{h.groupName}</span>{/if}
                {#if h.error}<div class="small bad-text" title={h.error}>last audit failed</div>{/if}
              </td>
              <td>
                {#if h.hardeningIndex !== null}
                  <span class="index">
                    <span class="gauge {indexTone(h.hardeningIndex)}" style:--v={h.hardeningIndex}></span>
                    <strong>{h.hardeningIndex}</strong>
                  </span>
                {:else if h.availability === 'Unavailable'}<span class="muted small">Lynis unavailable</span>
                {:else}<span class="nil" aria-label="none"></span>{/if}
              </td>
              <td class="num">{#if h.warnings}<span class="pill bad">{h.warnings}</span>{:else if h.warnings !== null}<span class="muted">{h.warnings}</span>{:else}<span class="nil" aria-label="none"></span>{/if}</td>
              <td class="num hide-sm">{#if h.suggestions !== null}{h.suggestions}{:else}<span class="nil" aria-label="none"></span>{/if}</td>
              <td class="hide-sm nowrap">{#if h.auditedAt}<Time iso={h.auditedAt} />{:else}<span class="muted">never</span>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>

  {#each [['Warnings', warnings], ['Most common suggestions', suggestions]] as const as [title, list] (title)}
    {#if list.length}
      <section class="card">
        <header><h2>{title}</h2><span class="hint">across the fleet, excluding accepted</span></header>
        <div class="table-wrap">
          <table class="table">
            <thead><tr><th title="Lynis test ID; links to its description on cisofy.com">Test</th><th>Finding</th><th class="num" title="Hosts with this finding, not counting those that accepted it">Hosts</th></tr></thead>
            <tbody>
              {#each list as i (i.testId)}
                <tr>
                  <td class="nowrap"><a class="mono" href={lynisUrl(i.testId)} target="_blank" rel="noreferrer">{i.testId}</a><div class="muted small">{i.category}</div></td>
                  <td class="finding">
                    {i.text}
                    {#if i.solution}<div class="muted small solution">{i.solution}</div>{/if}
                    {#if lynisNotes[i.testId]}<div class="small note"><Icon name="info" />{lynisNotes[i.testId].text}</div>{/if}
                  </td>
                  <td class="num hosts">
                    <strong>{i.hostCount}</strong>
                    <div class="small host-list">
                      {#each i.hosts.slice(0, 3) as h (h.id)}<a href="/hosts/{h.id}?tab=hardening">{h.name}</a>{/each}
                      {#if i.hostCount > 3}<span class="muted">+{i.hostCount - 3}</span>{/if}
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
    {/if}
  {/each}
{/if}

<style>
  .summary { margin-bottom: var(--space-md); }
  .strip { display: flex; flex-wrap: wrap; }
  .strip > .stat { flex: 0 0 auto; min-width: 176px; }
  .strip > .explain { display: block; flex: 1 1 320px; margin: 0; }
  .card + .card { margin-top: var(--space-md); }
  .name { font-weight: 500; margin-right: var(--space-xs); }
  .bad-text { color: var(--bad); }
  .index { display: inline-flex; align-items: center; gap: var(--space-xs); font-variant-numeric: tabular-nums; }
  .index .gauge { width: 72px; }
  .index strong { font-family: var(--font-display); font-weight: 600; }
  .finding { min-width: 240px; max-width: 560px; }
  .solution { margin-top: var(--space-3xs); }
  .note { display: flex; gap: var(--space-2xs); align-items: flex-start; margin-top: var(--space-2xs); color: var(--color-ink-2); }
  .note :global(.icon) { margin-top: var(--space-3xs); color: var(--color-accent); }
  .host-list a:focus-visible, .name:focus-visible { outline-offset: 1px; }
  .hosts { white-space: nowrap; }
  .hosts strong { font-family: var(--font-display); font-weight: 600; }
  .host-list { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 0 var(--space-xs); max-width: 220px; margin-left: auto; white-space: normal; }
  @media (max-width: 640px) {
    .finding { min-width: 200px; }
    .strip > .stat { flex: 1 1 50%; min-width: 0; }
    .strip > .stat .figure-value { font-size: var(--text-figure-s); }
  }
</style>
