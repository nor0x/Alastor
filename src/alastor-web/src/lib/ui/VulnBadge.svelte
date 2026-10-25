<script lang="ts">
  let { critical, high, total }: { critical: number | null; high: number | null; total: number | null } = $props();
</script>

{#if total !== null}
  {#if critical}<span class="pill bad" title="{critical} critical, {high ?? 0} high, {total} open CVEs">{critical} critical</span>
  {:else if high}<span class="pill warn" title="{high} high, {total} open CVEs">{high} high</span>
  {:else if total}<span class="pill muted" title="{total} open CVEs, none high or critical">{total} low/med</span>
  {:else}<span class="pill ok">none known</span>{/if}
{/if}
