<script lang="ts">
  let { pending, security }: { pending: number | null; security: number | null } = $props();

  // Alpine can't tell security updates apart (security is null): count everything as possibly one.
  const count = $derived(security ?? pending ?? 0);
  const label = $derived(security === null ? `${pending} pending` : security ? `${security} security` : pending ? `${pending} pending` : 'up to date');
  const tone = $derived(count > 0 ? (security === null ? 'warn' : 'bad') : pending ? 'muted' : 'ok');
</script>

{#if pending !== null}
  <span class="pill {tone}" title="{pending} pending update{pending === 1 ? '' : 's'}{security !== null ? `, ${security} security` : ''}">{label}</span>
{/if}
