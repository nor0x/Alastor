<script lang="ts">
  import { api, errorText, lynisUrl, type FleetHardening } from './api';
  import { indexTone, lynisNotes } from './hardening';
  import { refreshOn } from './live.svelte';
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
    <div class="stat">
      <span class="label">Average hardening index</span>
      <span class="big {indexTone(data.averageIndex)}">{data.averageIndex ?? '—'}<span class="of">/ 100</span></span>
    </div>
    <div class="stat">
      <span class="label">Hosts audited</span>
      <span class="big">{audited.length}<span class="of">/ {data.hosts.length}</span></span>
    </div>
    <p class="muted small explain">
      <a href="https://cisofy.com/lynis/" target="_blank" rel="noreferrer">Lynis</a> runs a few hundred tests and scores the host. A fresh install
      usually scores 55 to 65. Treat the checklist as advice: accept what doesn't apply on each host's <strong>Hardening</strong> tab.
    </p>
  </section>

  <section class="card">
    <header><h2>Hosts</h2><span class="hint">lowest index first</span></header>
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>Host</th><th>Index</th><th class="num">Warnings</th><th class="num hide-sm">Suggestions</th><th class="hide-sm">Audited</th></tr></thead>
        <tbody>
          {#each hostsSorted as h (h.hostId)}
            <tr>
              <td>
                <a href="/hosts/{h.hostId}?tab=hardening" class="name">{h.name}</a>
                {#if h.groupName}<span class="pill info">{h.groupName}</span>{/if}
                {#if h.error}<div class="small bad-text" title={h.error}>last audit failed</div>{/if}
              </td>
              <td>
                {#if h.hardeningIndex !== null}
                  <span class="index">
                    <span class="track"><span class="fill {indexTone(h.hardeningIndex)}" style:width="{h.hardeningIndex}%"></span></span>
                    <strong>{h.hardeningIndex}</strong>
                  </span>
                {:else if h.availability === 'Unavailable'}<span class="muted small">Lynis unavailable</span>
                {:else}<span class="muted">—</span>{/if}
              </td>
              <td class="num">{#if h.warnings}<span class="pill bad">{h.warnings}</span>{:else}<span class="muted">{h.warnings ?? '—'}</span>{/if}</td>
              <td class="num hide-sm">{h.suggestions ?? '—'}</td>
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
            <thead><tr><th>Test</th><th>Finding</th><th class="num">Hosts</th></tr></thead>
            <tbody>
              {#each list as i (i.testId)}
                <tr>
                  <td class="nowrap"><a class="mono" href={lynisUrl(i.testId)} target="_blank" rel="noreferrer">{i.testId}</a><div class="muted small">{i.category}</div></td>
                  <td class="finding">
                    {i.text}
                    {#if i.solution}<div class="muted small">→ {i.solution}</div>{/if}
                    {#if lynisNotes[i.testId]}<div class="small note">{lynisNotes[i.testId].text}</div>{/if}
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
  .summary { display: flex; flex-wrap: wrap; align-items: center; gap: 16px 40px; padding: 16px; margin-bottom: 16px; }
  .stat { display: flex; flex-direction: column; gap: 4px; }
  .label { font-size: 12px; color: var(--muted); }
  .big { font-size: 30px; font-weight: 600; line-height: 1; font-variant-numeric: tabular-nums; color: var(--text-strong); }
  .big.ok { color: var(--ok); }
  .big.warn { color: var(--warn); }
  .big.bad { color: var(--bad); }
  .of { font-size: 14px; font-weight: 400; color: var(--muted); margin-left: 4px; }
  .explain { flex: 1; min-width: 240px; margin: 0; }
  .card + .card { margin-top: 16px; }
  .name { font-weight: 600; margin-right: 6px; }
  .bad-text { color: var(--bad); }
  .index { display: inline-flex; align-items: center; gap: 8px; font-variant-numeric: tabular-nums; }
  .track { width: 72px; height: 6px; border-radius: 3px; background: var(--surface-2); overflow: hidden; }
  .fill { display: block; height: 100%; border-radius: 3px; background: var(--muted); }
  .fill.ok { background: var(--ok); }
  .fill.warn { background: var(--warn); }
  .fill.bad { background: var(--bad); }
  .finding { min-width: 240px; max-width: 560px; }
  .note { margin-top: 3px; color: var(--info); }
  .hosts { white-space: nowrap; }
  .host-list { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 0 6px; max-width: 220px; margin-left: auto; white-space: normal; }
  @media (max-width: 640px) {
    .finding { min-width: 0; }
  }
</style>
