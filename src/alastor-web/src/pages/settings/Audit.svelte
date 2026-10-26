<script lang="ts">
  import { api, type AuditEntry } from '../../lib/api';
  import { hostNames } from '../../lib/fleet.svelte';
  import { fullDate } from '../../lib/format';
  import Time from '../../lib/ui/Time.svelte';

  let entries = $state<AuditEntry[]>([]);
  let limit = $state(100);
  let q = $state('');

  $effect(() => {
    api<AuditEntry[]>(`/api/audit?limit=${limit}`).then((e) => (entries = e)).catch(() => {});
  });

  const shown = $derived(entries.filter((e) => !q || [e.actor, e.action, e.target ?? '', e.details ?? ''].some((s) => s.toLowerCase().includes(q.toLowerCase()))));

  // Targets like "Host:<guid>" or a bare host id read better as the host's name.
  function target(t: string | null) {
    if (!t) return '';
    const id = t.includes(':') ? t.split(':')[1] : t;
    const name = hostNames()[id];
    return name ? t.replace(id, name) : t;
  }
</script>

<section class="card">
  <header>
    <h2>Audit log</h2>
    <input class="field filter" type="search" placeholder="Filter…" bind:value={q} aria-label="Filter audit log" />
  </header>
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th class="hide-sm">Details</th></tr></thead>
      <tbody>
        {#each shown as e (e.id)}
          <tr>
            <td class="nowrap" title={fullDate(e.at)}><Time iso={e.at} /></td>
            <td class="nowrap">{e.actor}</td>
            <td class="mono small nowrap">{e.action}</td>
            <td class="small">{target(e.target)}</td>
            <td class="hide-sm small muted">{e.details ?? ''}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if entries.length === limit && limit < 500}
    <div class="more"><button class="btn" onclick={() => (limit = Math.min(500, limit + 200))}>Show more</button></div>
  {/if}
</section>

<style>
  h2 { white-space: nowrap; }
  .filter { flex: 0 1 260px; min-width: 0; min-height: var(--control-s); }
</style>
