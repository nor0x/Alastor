<script lang="ts">
  import type { FeedSource } from './api';
  import { number, timeAgo } from './format';

  let { sources, now }: { sources: FeedSource[]; now: number } = $props();

  const failing = $derived(sources.filter((s) => s.consecutiveFailures > 0));

  function status(s: FeedSource) {
    if (s.consecutiveFailures > 0) return 'failing';
    return s.lastSuccessAt ? 'ok' : 'pending';
  }

  function describe(s: FeedSource) {
    if (s.consecutiveFailures > 0)
      return `${s.name}: ${s.lastError ?? 'failed'} (${s.consecutiveFailures}× in a row). Last success ${timeAgo(s.lastSuccessAt, now)}; next try ${timeAgo(s.nextAttemptAt, now)}.`;
    if (!s.lastSuccessAt) return `${s.name}: first fetch pending`;
    return `${s.name}: updated ${timeAgo(s.lastSuccessAt, now)} · ${number.format(s.items)} items · next ${timeAgo(s.nextAttemptAt, now)}`;
  }
</script>

{#if sources.length}
  <details class="health" class:warn={failing.length > 0}>
    <summary>
      {#each sources as s (s.id)}
        <span class="dot {status(s)}" title={describe(s)}></span>
      {/each}
      <span class="label">
        {failing.length ? `${failing.length} of ${sources.length} sources failing` : `${sources.length} sources`}
      </span>
    </summary>
    <ul>
      {#each sources as s (s.id)}
        <li>
          <span class="dot {status(s)}"></span>
          <a href={s.homepage} target="_blank" rel="noopener noreferrer">{s.name}</a>
          <span class="detail">{describe(s).slice(s.name.length + 2)}</span>
        </li>
      {/each}
    </ul>
  </details>
{/if}

<style>
  .health { position: relative; font-size: 12px; color: var(--muted); }
  summary {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 999px;
    cursor: pointer;
    list-style: none;
  }
  summary::-webkit-details-marker { display: none; }
  .warn summary { border-color: color-mix(in srgb, var(--sev-medium) 50%, transparent); }
  .label { margin-left: 4px; }
  .warn .label { color: var(--sev-medium); }

  .dot { width: 8px; height: 8px; border-radius: 50%; flex: none; background: var(--sev-info); }
  .dot.ok { background: var(--sev-low); }
  .dot.failing { background: var(--sev-medium); }
  .dot.pending { background: transparent; border: 1px solid var(--muted); }

  ul {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    z-index: 20;
    width: min(440px, calc(100vw - 32px));
    margin: 0;
    padding: 8px 0;
    list-style: none;
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  }
  li { display: grid; grid-template-columns: 8px auto 1fr; align-items: baseline; gap: 8px; padding: 5px 12px; }
  li .dot { align-self: center; }
  li a { color: var(--text-strong); white-space: nowrap; }
  .detail { color: var(--muted); }
  @media (max-width: 640px) { ul { left: 0; right: auto; } }
</style>
