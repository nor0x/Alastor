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
      <span class="dots">
        {#each sources as s (s.id)}
          <span class="dot {status(s)}" title={describe(s)}></span>
        {/each}
      </span>
      <span class="label">
        {failing.length ? `${failing.length} of ${sources.length} sources failing` : `${sources.length} sources`}
      </span>
    </summary>
    <ul>
      {#each sources as s (s.id)}
        <li>
          <span class="dot {status(s)}"></span>
          <a href={s.homepage} target="_blank" rel="noopener noreferrer">{s.name}</a>
          {#if status(s) === 'ok'}
            <span class="detail parts">
              <span>updated {timeAgo(s.lastSuccessAt, now)}</span>
              <span>{number.format(s.items)} items</span>
              <span>next {timeAgo(s.nextAttemptAt, now)}</span>
            </span>
          {:else}
            <span class="detail" class:bad={status(s) === 'failing'}>{describe(s).slice(s.name.length + 2)}</span>
          {/if}
        </li>
      {/each}
    </ul>
  </details>
{/if}

<style>
  .health { position: relative; font-size: var(--text-sm); color: var(--muted); }
  summary {
    display: flex;
    align-items: center;
    gap: var(--space-xs);
    min-height: var(--control);
    padding: 0 var(--space-sm);
    border: var(--rule-hair) solid var(--color-rule-2);
    border-radius: var(--radius-input);
    background: var(--color-key-face);
    font-family: var(--font-display);
    font-weight: 500;
    cursor: pointer;
    list-style: none;
    white-space: nowrap;
  }
  summary::-webkit-details-marker { display: none; }
  summary:hover { border-color: var(--color-ink-2); }
  summary:active { background: var(--color-paper-2); }
  summary:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
  .health[open] summary { background: var(--color-paper-2); }
  .dots { display: inline-flex; gap: var(--space-3xs); }
  .warn summary { border-color: color-mix(in oklab, var(--warn) 45%, var(--border)); }
  .warn .label { color: var(--warn); }

  .dot { width: 8px; height: 8px; border-radius: 2px; flex: none; background: var(--color-rule-2); }
  .dot.ok { background: var(--ok); }
  .dot.failing { background: var(--warn); }
  .dot.pending { background: transparent; box-shadow: inset 0 0 0 1px var(--muted); }

  ul {
    position: absolute;
    right: 0;
    top: calc(100% + var(--space-2xs));
    z-index: var(--z-dropdown);
    width: 440px;
    margin: 0;
    padding: var(--space-2xs) 0;
    list-style: none;
    background: var(--surface);
    border: var(--rule-hair) solid var(--border-strong);
    border-radius: var(--radius-card);
    box-shadow: var(--shadow-float);
  }
  li { display: grid; grid-template-columns: 8px auto minmax(0, 1fr); align-items: baseline; gap: var(--space-xs); padding: var(--space-xs) var(--space-sm); }
  li + li { border-top: var(--rule-hair) solid var(--border); }
  li .dot { align-self: center; }
  li a { color: var(--text-strong); font-family: var(--font-display); font-weight: 500; white-space: nowrap; }
  .detail { color: var(--muted); }
  .detail.bad { color: var(--warn); }
  .parts { display: flex; flex-wrap: wrap; gap: 0 var(--space-xs); }
  .parts > span + span { padding-left: var(--space-xs); border-left: var(--rule-hair) solid var(--color-rule-2); }
  @media (max-width: 640px) {
    ul { position: static; width: auto; margin-top: var(--space-2xs); box-shadow: none; }
    li { grid-template-columns: 8px minmax(0, 1fr); }
    li .detail { grid-column: 2; }
  }
</style>
