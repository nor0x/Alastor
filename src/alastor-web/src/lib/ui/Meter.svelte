<script lang="ts">
  // A compact usage bar for tables. The number is always printed, so the colour is never the only signal.
  let { value, warn = 80, bad = 95 }: { value: number; warn?: number; bad?: number } = $props();
  const tone = $derived(value >= bad ? 'bad' : value >= warn ? 'warn' : 'ok');
</script>

<span class="meter" title="{value.toFixed(1)}%">
  <span class="track"><span class="fill {tone}" style:width="{Math.min(100, Math.max(0, value))}%"></span></span>
  <span class="num">{value.toFixed(0)}%</span>
</span>

<style>
  .meter { display: inline-flex; align-items: center; gap: 6px; }
  .track { width: 48px; height: 6px; border-radius: 3px; background: var(--surface-2); overflow: hidden; }
  .fill { display: block; height: 100%; border-radius: 3px; background: var(--muted); }
  .fill.ok { background: var(--muted); }
  .fill.warn { background: var(--warn); }
  .fill.bad { background: var(--bad); }
  .num { font-variant-numeric: tabular-nums; min-width: 32px; text-align: right; font-size: 12px; }
</style>
