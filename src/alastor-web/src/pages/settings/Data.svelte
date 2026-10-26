<script lang="ts">
  import { api, errorText, type ServerData } from '../../lib/api';
  import { bytes } from '../../lib/format';
  import { toast } from '../../lib/toast.svelte';
  import { confirm } from '../../lib/ui/confirm.svelte';
  import Time from '../../lib/ui/Time.svelte';

  let data = $state<ServerData | null>(null);
  let busy = $state('');

  const load = async () => (data = await api<ServerData>('/api/system/data').catch(() => data));
  $effect(() => {
    load();
  });

  async function run(id: string, label: string, path: string) {
    busy = id;
    try {
      const r = await api<{ freedBytes?: number; removed?: Record<string, number> }>(path, { method: 'POST' });
      if (r.removed) {
        const parts = Object.entries(r.removed).map(([k, v]) => `${v} ${k}`);
        toast(parts.length ? `Removed ${parts.join(', ')}.` : 'Nothing was old enough to remove.');
      } else toast(`${label}: ${bytes(r.freedBytes ?? 0)} freed.`);
      load();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      busy = '';
    }
  }

  async function compact() {
    if (!(await confirm('Compact the database?', 'SQLite rewrites the file without its free space. Writes wait until it finishes, usually a few seconds.', { confirmLabel: 'Compact' }))) return;
    run('compact', 'Compacted', '/api/system/data/compact');
  }

  const rows = $derived(data?.tables.filter((t) => t.rows > 0) ?? []);
</script>

<div class="stack">
  <section class="card">
    <header><h2>Database</h2><span class="hint">{data?.provider ?? ''}</span></header>
    {#if data}
      <div class="card-body stack">
        <dl class="facts">
          <div><dt>Size</dt><dd>{bytes(data.databaseBytes)}</dd></div>
          {#if data.freeBytesInDatabase !== null}<div><dt>Free space inside</dt><dd>{bytes(data.freeBytesInDatabase)}</dd></div>{/if}
          {#if data.diskFreeBytes !== null}<div><dt>Disk free</dt><dd>{bytes(data.diskFreeBytes)}</dd></div>{/if}
          {#if data.lastCompactedAt}<div><dt>Compacted</dt><dd><Time iso={data.lastCompactedAt} /></dd></div>{/if}
        </dl>
        {#if data.databasePath}<p class="muted small m0 mono path">{data.databasePath}</p>{/if}
        <p class="muted small m0">
          Old rows are removed on the retention schedule below. Deleted rows leave free space inside the SQLite file; it's compacted automatically once a
          week when that's over a quarter of the file, or now with the button.
        </p>
        <div class="actions-row">
          <button class="btn" disabled={!!busy} onclick={() => run('prune', 'Pruned', '/api/system/data/prune')}>{busy === 'prune' ? 'Removing…' : 'Remove old data now'}</button>
          {#if data.provider === 'sqlite'}<button class="btn" disabled={!!busy} onclick={compact}>{busy === 'compact' ? 'Compacting…' : 'Compact database'}</button>{/if}
        </div>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Table</th><th class="num">Rows</th>{#if data.provider === 'postgres'}<th class="num">Size</th>{/if}</tr></thead>
          <tbody>
            {#each rows as t (t.table)}
              <tr><td class="mono">{t.table}</td><td class="num">{t.rows.toLocaleString()}</td>{#if data.provider === 'postgres'}<td class="num">{t.bytes !== null ? bytes(t.bytes) : '—'}</td>{/if}</tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  {#if data}
    <section class="card">
      <header><h2>Files</h2></header>
      {#if data.cleanups.some((c) => c.items > 0)}
        <ul class="cleanups">
          {#each data.cleanups.filter((c) => c.items > 0) as c (c.id)}
            <li>
              <div>
                <div class="title">{c.title} <span class="muted">· {bytes(c.bytes)}</span></div>
                <p class="muted small m0">{c.description}</p>
              </div>
              <button class="btn small" disabled={!!busy} onclick={() => run(c.id, c.title, `/api/system/data/cleanup/${c.id}`)}>{busy === c.id ? 'Removing…' : 'Remove'}</button>
            </li>
          {/each}
        </ul>
      {:else}
        <p class="muted small card-body m0">Nothing to clean up: every mirrored database is in use, and no older server version left files behind.</p>
      {/if}
      {#if data.folders.length}
        <div class="table-wrap">
          <table class="table">
            <thead><tr><th>Folder</th><th class="num">Size</th></tr></thead>
            <tbody>
              {#each data.folders as f (f.path)}
                <tr><td><span class="mono small path">{f.path}</span><div class="muted small">{f.description}</div></td><td class="num nowrap">{bytes(f.bytes)}</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <section class="card">
      <header><h2>Retention</h2><span class="hint">server settings</span></header>
      <p class="muted small intro">Set with environment variables (<code>ALASTOR_AUDITRETENTION=180d</code>, …) and applied after a restart.</p>
      <div class="table-wrap">
        <table class="table">
          <tbody>
            {#each data.retention as r (r.key)}
              <tr><td><span class="mono small">ALASTOR_{r.key.toUpperCase()}</span><div class="muted small">{r.description}</div></td><td class="mono">{r.value}</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}
</div>

<style>
  .m0 { margin: 0; max-width: 80ch; }
  .intro { margin: 0; padding: var(--space-sm) var(--space-md); }
  .facts { display: flex; flex-wrap: wrap; gap: var(--space-md) var(--space-xl); margin: 0; }
  .facts dt { font-size: var(--text-sm); color: var(--muted); }
  .facts dd { margin: 0; font-family: var(--font-display); font-size: var(--text-lg); color: var(--text-strong); }
  .path { overflow-wrap: anywhere; }
  .actions-row { display: flex; gap: var(--space-xs); flex-wrap: wrap; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .cleanups { list-style: none; margin: 0; padding: 0; }
  .cleanups li { display: flex; gap: var(--space-md); align-items: center; justify-content: space-between; padding: var(--space-sm) var(--space-md); border-bottom: var(--rule-hair) solid var(--border); }
  .title { font-family: var(--font-display); font-weight: 500; color: var(--text-strong); }
</style>
