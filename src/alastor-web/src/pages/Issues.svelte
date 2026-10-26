<script lang="ts">
  import Icon from '../lib/ui/Icon.svelte';
  import { untrack } from 'svelte';
  import { api, errorText, severities, type IssueList as IssueListDto } from '../lib/api';
  import { fleet } from '../lib/fleet.svelte';
  import { refreshIssues } from '../lib/issues.svelte';
  import { refreshOn } from '../lib/live.svelte';
  import { route } from '../lib/router.svelte';
  import { number } from '../lib/format';
  import IssueList from '../lib/IssueList.svelte';

  interface Filters { state: string; hostId: string; minSeverity: string; rule: string }
  const keys: (keyof Filters)[] = ['state', 'hostId', 'minSeverity', 'rule'];
  const states: [string, string][] = [['', 'Open'], ['unacknowledged', 'Unacknowledged'], ['acknowledged', 'Acknowledged'], ['resolved', 'Resolved']];

  function read(): Filters {
    const p = new URLSearchParams(route.search);
    return { state: p.get('state') ?? '', hostId: p.get('hostId') ?? '', minSeverity: p.get('minSeverity') ?? '', rule: p.get('rule') ?? '' };
  }

  let filters = $state<Filters>(read());
  let data = $state<IssueListDto | null>(null);
  let rules = $state<{ key: string; label: string }[]>([]);
  let loading = $state(true);
  let error = $state('');

  $effect(() => {
    void route.search;
    const f = read();
    if (untrack(() => keys.some((k) => f[k] !== filters[k]))) filters = f;
  });

  async function load() {
    loading = true;
    const p = new URLSearchParams();
    if (filters.state) p.set('state', filters.state);
    if (filters.hostId) p.set('hostId', filters.hostId);
    if (filters.minSeverity) p.set('minSeverity', filters.minSeverity);
    if (filters.rule) p.set('rule', filters.rule);
    try {
      data = await api<IssueListDto>(`/api/issues?${p}`);
      error = '';
    } catch (e) {
      error = errorText(e);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    const qs = new URLSearchParams(Object.entries(filters).filter(([, v]) => v)).toString();
    history.replaceState(null, '', qs ? `/issues?${qs}` : '/issues');
    route.search = qs ? `?${qs}` : '';
    load();
  });

  $effect(() => {
    api<{ key: string; label: string }[]>('/api/issues/rules').then((r) => (rules = r)).catch(() => {});
    return refreshOn(['issuesChanged'], load, 30_000);
  });

  function set(change: Partial<Filters>) {
    filters = { ...filters, ...change };
  }

  function changed() {
    load();
    refreshIssues();
  }

  const s = $derived(data?.summary);
  const empty: Record<string, string> = {
    '': 'No open issues. Every host is in the state its policy asks for.',
    unacknowledged: 'Nothing waiting for a look. Acknowledged issues are under “Acknowledged”.',
    acknowledged: 'No acknowledged issues.',
    resolved: 'Nothing resolved yet. Issues close on their own when the condition clears.',
  };
</script>

<div class="page-head">
  <div>
    <h1>Issues</h1>
    <p class="sub">Open problems across the fleet, derived from each host's latest reports. They close on their own when the condition clears.</p>
  </div>
</div>

{#if s}
  <section class="card summary" aria-label="Unacknowledged issues by severity">
    <div class="ledger">
      {#each severities.slice(0, 4) as sev (sev)}
        {@const n = s.unacknowledgedBySeverity[sev] ?? 0}
        <button class="ledger-cell" aria-pressed={filters.minSeverity === sev && filters.state === 'unacknowledged'}
          onclick={() => set({ state: 'unacknowledged', minSeverity: sev })}>
          <span class="sev sev-{sev.toLowerCase()}">{sev}</span>
          <span class="figure-value" class:zero={n === 0}>{number.format(n)}</span>
          <span class="figure-foot">unacknowledged</span>
        </button>
      {/each}
      <div class="totals">
        <span class="figure-label">All open</span>
        <span class="figure-value">{number.format(s.open)}</span>
        <span class="figure-foot">{number.format(s.acknowledged)} acknowledged</span>
      </div>
    </div>
  </section>
{/if}

<div class="filterbar">
  <div class="seg" role="group" aria-label="State">
    {#each states as [v, label] (v)}
      <button class:on={filters.state === v} aria-pressed={filters.state === v} onclick={() => set({ state: v })}>{label}</button>
    {/each}
  </div>
  <select class="field" value={filters.hostId} onchange={(e) => set({ hostId: e.currentTarget.value })} aria-label="Host">
    <option value="">All hosts</option>
    {#each fleet.hosts as h (h.id)}<option value={h.id}>{h.name}</option>{/each}
  </select>
  <select class="field" value={filters.minSeverity} onchange={(e) => set({ minSeverity: e.currentTarget.value })} aria-label="Minimum severity">
    <option value="">Any severity</option>
    {#each severities.slice(0, 4) as sev (sev)}<option value={sev}>{sev === 'Critical' ? 'Critical' : `${sev} and above`}</option>{/each}
  </select>
  <select class="field" value={filters.rule} onchange={(e) => set({ rule: e.currentTarget.value })} aria-label="Kind">
    <option value="">All kinds</option>
    {#each rules as r (r.key)}<option value={r.key}>{r.label}</option>{/each}
  </select>
  {#if keys.some((k) => filters[k])}<button class="btn ghost" onclick={() => (filters = { state: '', hostId: '', minSeverity: '', rule: '' })}>Clear</button>{/if}
</div>

{#if error}<div class="banner bad" role="alert"><Icon name="error" /><p>Couldn't load issues: {error}</p><button class="btn small" onclick={load}>Retry</button></div>{/if}

<section class="card" class:dim={loading && !!data}>
  {#if data?.items.length}
    <IssueList issues={data.items} onchange={changed} />
  {:else if loading && !data}
    <div class="skeleton-block"></div>
  {:else}
    <div class="empty">{filters.hostId || filters.minSeverity || filters.rule ? 'No issues match these filters.' : empty[filters.state] ?? empty['']}</div>
  {/if}
</section>

<style>
  .filterbar .seg { max-width: 100%; overflow-x: auto; }
  .summary { margin-bottom: var(--space-md); overflow: hidden; }
  .summary .ledger { grid-template-columns: repeat(auto-fit, minmax(min(100%, 150px), 1fr)); }
  button.ledger-cell { align-items: flex-start; border: 0; border-radius: 0; background: none; text-align: left; font: inherit; cursor: pointer; }
  button.ledger-cell:hover { background: var(--color-paper-2); }
  button.ledger-cell:active { background: var(--color-paper-3); }
  button.ledger-cell:focus-visible { outline-offset: -2px; }
  button.ledger-cell[aria-pressed='true'] { background: var(--color-accent-wash); box-shadow: 1px 0 0 var(--border), 0 1px 0 var(--border), inset 0 -2px 0 var(--color-accent); }
  .figure-value.zero { color: var(--muted); }
  .totals { background: var(--color-paper-2); }
  .dim { opacity: 0.6; transition: opacity var(--dur-short) var(--ease-out); }
  .banner { margin-bottom: var(--space-xs); align-items: center; }
  .banner p { flex: 1; }
</style>
