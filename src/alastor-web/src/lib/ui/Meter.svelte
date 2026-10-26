<script lang="ts">
  // A compact usage bar for tables. The number is always printed, so the colour is never the only signal.
  let { value, warn = 80, bad = 95 }: { value: number; warn?: number; bad?: number } = $props();
  const tone = $derived(value >= bad ? 'bad' : value >= warn ? 'warn' : 'ok');
</script>

<span class="meter" title="{value.toFixed(1)}%">
  <span class="gauge {tone === 'ok' ? '' : tone}" style:--v={Math.min(100, Math.max(0, value))}></span>
  <span class="num">{value.toFixed(0)}%</span>
</span>

<style>
  .meter { display: inline-flex; align-items: center; gap: var(--space-xs); }
  .gauge { width: 50px; --tone: var(--color-ink-2); }
  .gauge.warn { --tone: var(--warn); }
  .gauge.bad { --tone: var(--bad); }
  .num { font-variant-numeric: tabular-nums; min-width: 32px; text-align: right; font-size: var(--text-sm); }
</style>
