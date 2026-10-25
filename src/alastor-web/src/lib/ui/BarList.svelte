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
  .bars { list-style: none; margin: 0; padding: 6px 16px 10px; display: flex; flex-direction: column; gap: 6px; }
  li { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(60px, 2fr) auto; align-items: center; gap: 10px; font-size: 13px; }
  .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .name a { font-family: var(--mono); font-size: 12.5px; }
  .note { margin-left: 6px; color: var(--muted); font-size: 11.5px; }
  .track { height: 8px; }
  .fill { display: block; height: 100%; min-width: 2px; border-radius: 0 4px 4px 0; background: var(--info); opacity: 0.85; }
  .num { min-width: 36px; text-align: right; font-variant-numeric: tabular-nums; color: var(--text-strong); }
</style>
