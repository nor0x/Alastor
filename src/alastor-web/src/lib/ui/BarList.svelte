<script lang="ts">
  import { number } from '../format';

  // Ranked horizontal bars: a label, a bar scaled to the largest value, and the number printed beside it.
  // One series, so one colour; the bar only helps compare, the number is the value.
  let { items, label = 'Value' }: {
    items: { key: string; label: string; value: number; href?: string; note?: string }[];
    label?: string;
  } = $props();

  const max = $derived(Math.max(1, ...items.map((i) => i.value)));
</script>

<ul class="bars" aria-label={label}>
  {#each items as it (it.key)}
    <li>
      <span class="name">
        {#if it.href}<a href={it.href}>{it.label}</a>{:else}{it.label}{/if}
        {#if it.note}<span class="note">{it.note}</span>{/if}
      </span>
      <span class="track"><span class="fill" style:width="{(it.value / max) * 100}%"></span></span>
      <span class="num">{number.format(it.value)}</span>
    </li>
  {/each}
</ul>

<style>
  .bars { list-style: none; margin: 0; padding: var(--space-xs) var(--space-md) var(--space-sm); display: flex; flex-direction: column; }
  li { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(60px, 2fr) auto; align-items: center; gap: var(--space-sm); min-height: 36px; font-size: var(--text-md); }
  li + li { border-top: var(--rule-hair) solid var(--border); }
  .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .name a { font-family: var(--mono); font-size: var(--text-code); }
  .note { margin-left: var(--space-xs); color: var(--muted); font-size: var(--text-xs); }
  .track { height: 10px; background: var(--color-paper-3); border-radius: 2px; }
  .fill { display: block; height: 100%; min-width: 2px; border-radius: 2px; background: var(--color-accent); }
  .num { min-width: 36px; text-align: right; font-family: var(--font-display); font-weight: 600; font-variant-numeric: tabular-nums; color: var(--text-strong); }
</style>
