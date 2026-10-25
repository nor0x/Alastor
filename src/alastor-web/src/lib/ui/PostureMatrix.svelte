<script lang="ts">
  import type { PostureMatrix } from '../api';

  // Hosts × security areas. Every cell has an icon and a word, so state never rests on colour; each links to the
  // host tab that explains it. Most troubled hosts first.
  let { matrix }: { matrix: PostureMatrix } = $props();

  const icon: Record<string, string> = { ok: '✓', warn: '!', bad: '✕', unknown: '?', off: '–' };
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
                  <span class="ico" aria-hidden="true">{icon[cell.status] ?? '?'}</span><span class="lbl">{cell.label}</span>
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
  .matrix { width: 100%; border-collapse: separate; border-spacing: 3px; font-size: 12px; }
  th { color: var(--muted); font-weight: 500; text-align: left; padding: 4px 6px; white-space: nowrap; }
  th.host { padding-left: 13px; }
  tbody th.host a { color: var(--text-strong); font-weight: 500; font-size: 13px; }
  td { padding: 0; min-width: 96px; }
  .cell {
    display: flex; align-items: center; gap: 6px; padding: 5px 8px; border-radius: 4px; color: var(--text);
    background: var(--surface-2); white-space: nowrap; overflow: hidden;
  }
  .cell:hover { text-decoration: none; outline: 1px solid var(--border-strong); }
  .lbl { overflow: hidden; text-overflow: ellipsis; }
  .ico { width: 14px; flex: none; text-align: center; font-weight: 700; color: var(--muted); }
  .cell.ok { background: var(--ok-bg); }
  .cell.ok .ico { color: var(--ok); }
  .cell.warn { background: var(--warn-bg); }
  .cell.warn .ico { color: var(--warn); }
  .cell.bad { background: var(--bad-bg); color: var(--text-strong); }
  .cell.bad .ico { color: var(--bad); }
  .cell.unknown, .cell.off { color: var(--muted); }
</style>
