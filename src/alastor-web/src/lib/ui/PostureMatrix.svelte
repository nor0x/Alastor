<script lang="ts">
  import type { PostureMatrix } from '../api';
  import Icon, { type IconName } from './Icon.svelte';

  // Hosts × security areas. Every cell has an icon and a word, so state never rests on colour; each links to the
  // host tab that explains it. Most troubled hosts first.
  let { matrix }: { matrix: PostureMatrix } = $props();

  // Unknown (not reported yet) and off (opt-in, not enabled) get no icon: their word is enough and they shouldn't draw the eye.
  const icon: Record<string, IconName> = { ok: 'check', warn: 'alert', bad: 'error' };
  const weight: Record<string, number> = { bad: 100, warn: 10, unknown: 0, off: 0, ok: 0 };
  const rows = $derived(
    [...matrix.rows].sort((a, b) => score(b) - score(a) || a.name.localeCompare(b.name)),
  );
  function score(r: PostureMatrix['rows'][number]) {
    return Object.values(r.cells).reduce((s, c) => s + (weight[c.status] ?? 0), 0);
  }
  const href = (hostId: string, tab: string) => (tab === 'overview' ? `/hosts/${hostId}` : `/hosts/${hostId}?tab=${tab}`);
</script>

<div class="table-wrap">
  <table class="matrix">
    <thead>
      <tr>
        <th class="host">Host</th>
        {#each matrix.columns as c (c.key)}<th>{c.label}</th>{/each}
      </tr>
    </thead>
    <tbody>
      {#each rows as r (r.hostId)}
        <tr>
          <th class="host" scope="row"><a href="/hosts/{r.hostId}">{r.name}</a></th>
          {#each matrix.columns as c (c.key)}
            {@const cell = r.cells[c.key]}
            <td>
              {#if cell}
                <a class="cell {cell.status}" href={href(r.hostId, c.tab)} title="{c.label}: {cell.label}">
                  {#if icon[cell.status]}<Icon name={icon[cell.status]} size={14} />{:else}<span class="nil" aria-hidden="true"></span>{/if}<span class="lbl">{cell.label}</span>
                </a>
              {/if}
            </td>
          {/each}
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .table-wrap { padding: var(--space-2xs) var(--space-sm) var(--space-sm); }
  .matrix { width: 100%; border-collapse: separate; border-spacing: var(--space-2xs); font-size: var(--text-sm); }
  th { padding: var(--space-2xs) var(--space-xs); color: var(--muted); font-family: var(--font-display); font-weight: 500; text-align: left; white-space: nowrap; }
  tbody th.host a { color: var(--text-strong); font-size: var(--text-md); }
  td { padding: 0; min-width: 104px; }
  /* A cell is the word and one icon on a quiet tray; only the icon and a tinted tray carry the tone. */
  .cell {
    display: flex; align-items: center; gap: var(--space-xs); min-height: 32px; padding: 0 var(--space-xs);
    border: var(--rule-hair) solid transparent; border-radius: 4px; background: var(--color-paper-2); color: var(--color-ink-2);
    white-space: nowrap; overflow: hidden;
  }
  .cell:hover { text-decoration: none; border-color: var(--border-strong); color: var(--text-strong); }
  .cell:focus-visible { outline-offset: 1px; }
  .lbl { overflow: hidden; text-overflow: ellipsis; }
  .cell .nil { width: 14px; flex: none; }
  .cell.ok :global(.icon) { color: var(--ok); }
  .cell.warn { background: var(--warn-bg); }
  .cell.warn :global(.icon) { color: var(--warn); }
  .cell.bad { background: var(--bad-bg); color: var(--text-strong); }
  .cell.bad :global(.icon) { color: var(--bad); }
  .cell.unknown, .cell.off { color: var(--muted); }
</style>
