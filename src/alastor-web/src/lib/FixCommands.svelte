<script lang="ts">
  import type { CommandGroup } from './baseline';
  import CopyButton from './ui/CopyButton.svelte';

  let { groups, tab = 'baseline' }: { groups: CommandGroup[]; tab?: string } = $props();
</script>

<div class="commands">
  {#each groups as g, gi (gi)}
    <div class="group">
      {#if g.hosts.length}
        <span class="on muted small">On {#each g.hosts as h, i (h.id)}{i ? ', ' : ''}<a href="/hosts/{h.id}?tab={tab}">{h.name}</a>{/each}</span>
      {/if}
      {#each g.commands as cmd, i (i)}
        <div class="cmd"><code>{cmd}</code><CopyButton text={cmd.replace(/\s+#.*$/, '')} /></div>
      {/each}
    </div>
  {/each}
  <p class="muted small">Run on the host as an admin. Lines after <code>#</code> are notes and aren't copied.</p>
</div>

<style>
  .commands, .group { display: flex; flex-direction: column; gap: var(--space-xs); }
  .commands { gap: var(--space-sm); }
  .commands p { margin: 0; }
</style>
