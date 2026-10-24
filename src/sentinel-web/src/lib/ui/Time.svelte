<script lang="ts">
  import { fullDate, timeAgo } from '../format';
  import { clock } from './clock.svelte';

  let { iso, empty = 'never' }: { iso: string | null; empty?: string } = $props();
</script>

{#if iso}<time datetime={iso} title={fullDate(iso)}>{timeAgo(iso, clock.now)}</time>{:else}<span class="muted">{empty}</span>{/if}
