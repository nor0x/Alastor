<script lang="ts">
  import { api, type LogLine } from '../../lib/api';
  import LogTable from '../../lib/ui/LogTable.svelte';

  // The server's own log since it last started, kept in memory. Older lines are in the journal.
  let lines = $state<LogLine[] | null>(null);
  let busy = $state(false);

  async function load() {
    busy = true;
    try {
      lines = await api<LogLine[]>('/api/system/logs?limit=2000');
    } catch {
      lines ??= [];
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    load();
    const t = setInterval(() => {
      if (document.visibilityState === 'visible') load();
    }, 15_000);
    return () => clearInterval(t);
  });
</script>

<section class="card">
  <header>
    <h2>Server log</h2>
    <span class="hint">since the server started · older lines: <code>journalctl -u alastor-server</code></span>
    <button class="btn small" onclick={load} disabled={busy}>Refresh</button>
  </header>
  <LogTable {lines} empty="Nothing logged since the server started." />
</section>

<style>
  header .hint { flex: 1; }
</style>
