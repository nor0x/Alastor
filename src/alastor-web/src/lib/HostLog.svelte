<script lang="ts">
  import { untrack } from 'svelte';
  import { api, type LogLine } from './api';
  import { on, refreshOn } from './live.svelte';
  import CopyButton from './ui/CopyButton.svelte';
  import LogTable from './ui/LogTable.svelte';

  // The agent's own log: what it installed, applied and skipped, and why. Lines arrive with each heartbeat, so an
  // offline agent shows what it logged before it went quiet; the journal on the host has the rest.
  let { hostId, online }: { hostId: string; online: boolean } = $props();

  let lines = $state<LogLine[] | null>(null);
  const load = async () => (lines = await api<LogLine[]>(`/api/hosts/${hostId}/logs`).catch(() => lines ?? []));

  $effect(() => {
    void hostId;
    lines = null;
    untrack(load);
    const offs = [
      on('hostUpdated', (h: { id: string }) => {
        if (h.id === hostId) load();
      }),
      refreshOn([], load, 60_000),
    ];
    return () => offs.forEach((o) => o());
  });

  const journal = 'sudo journalctl -u alastor-agent -n 200 --no-pager';
</script>

<section class="card">
  <header>
    <h2>Agent log</h2>
    <span class="hint">newest 1,000 lines, sent with each heartbeat</span>
  </header>
  {#if !online}
    <div class="offline">
      <p class="small">The agent is offline, so this ends at its last heartbeat. To see why it stopped, read the journal on the host:</p>
      <div class="cmd"><code>{journal}</code><CopyButton text={journal} /></div>
    </div>
  {/if}
  <LogTable {lines} empty="No log lines yet. Older agents don't send their log; update the agent to see it here." />
</section>

<style>
  h2 { white-space: nowrap; }
  .offline { display: grid; gap: var(--space-xs); padding: var(--space-sm) var(--space-md) 0; }
  .offline p { margin: 0; }
</style>
