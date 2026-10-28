<script lang="ts">
  import type { LogLine } from '../api';
  import Time from './Time.svelte';

  // A log, newest first, with a level switch and a text filter. Shared by a host's Agent log and the Server log.
  let { lines, empty }: { lines: LogLine[] | null; empty: string } = $props();

  let level = $state<'all' | 'problems'>('all');
  let q = $state('');

  const shown = $derived(
    (lines ?? []).filter(
      (l) => (level === 'all' || l.level === 'warning' || l.level === 'error') && (!q || `${l.source} ${l.message}`.toLowerCase().includes(q.toLowerCase())),
    ),
  );
  const problems = $derived((lines ?? []).filter((l) => l.level === 'warning' || l.level === 'error').length);
  const tone: Record<LogLine['level'], string> = { debug: 'muted', info: 'muted', warning: 'warn', error: 'bad' };
</script>

<div class="filterbar">
  <div class="seg" role="group" aria-label="Levels">
    <button class:on={level === 'all'} aria-pressed={level === 'all'} onclick={() => (level = 'all')}>All</button>
    <button class:on={level === 'problems'} aria-pressed={level === 'problems'} onclick={() => (level = 'problems')}>Warnings and errors {problems}</button>
  </div>
  <input class="field grow" type="search" placeholder="Filter…" bind:value={q} aria-label="Filter log lines" />
</div>

{#if lines === null}
  <div class="empty">Loading…</div>
{:else if !lines.length}
  <div class="empty">{empty}</div>
{:else if !shown.length}
  <div class="empty">No lines match.</div>
{:else}
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>When</th><th>Level</th><th class="hide-sm">Source</th><th>Message</th></tr></thead>
      <tbody>
        {#each shown as l (l.id)}
          <tr>
            <td class="nowrap small"><Time iso={l.at} /></td>
            <td><span class="pill {tone[l.level]}">{l.level}</span></td>
            <td class="hide-sm mono small nowrap">{l.source}</td>
            <td class="msg mono small">{l.message}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

<style>
  .filterbar { margin: 0; padding: var(--space-sm) var(--space-md); }
  .msg { white-space: pre-wrap; overflow-wrap: anywhere; min-width: 16ch; }
</style>
