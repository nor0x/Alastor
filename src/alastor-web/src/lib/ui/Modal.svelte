<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';

  let { open = $bindable(false), title, wide = false, children, footer }: {
    open?: boolean;
    title: string;
    wide?: boolean;
    children: Snippet;
    footer?: Snippet;
  } = $props();

  let dialog = $state<HTMLDialogElement>();

  // The native <dialog> gives focus trapping, Escape and the backdrop for free.
  $effect(() => {
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    else if (!open && dialog.open) dialog.close();
  });
</script>

<dialog bind:this={dialog} class:wide onclose={() => (open = false)} onclick={(e) => e.target === dialog && (open = false)}>
  {#if open}
    <header>
      <h2>{title}</h2>
      <button class="x" aria-label="Close" onclick={() => (open = false)}><Icon name="close" /></button>
    </header>
    <div class="body">{@render children()}</div>
    {#if footer}<footer>{@render footer()}</footer>{/if}
  {/if}
</dialog>

<style>
  dialog {
    width: 520px; max-width: calc(100% - 2 * var(--space-md));
    max-height: calc(100dvh - 2 * var(--space-lg));
    padding: 0;
    border: var(--rule-hair) solid var(--border);
    border-radius: var(--radius-card);
    background: var(--color-key-face);
    color: var(--text);
    box-shadow: var(--shadow-float);
  }
  @supports (corner-shape: bevel) { dialog { border-radius: var(--cut-l) 4px; corner-shape: bevel round; } }
  dialog.wide { width: 820px; }
  dialog::backdrop { background: var(--color-scrim); }
  header { display: flex; justify-content: space-between; align-items: center; gap: var(--space-sm); padding: var(--space-md) var(--space-md) var(--space-md) var(--space-lg); border-bottom: var(--rule-hair) solid var(--border); }
  h2 { margin: 0; font-size: var(--text-xl); }
  .x { display: inline-grid; place-items: center; width: 32px; height: 32px; border: 0; border-radius: var(--radius-input); background: none; color: var(--muted); cursor: pointer; }
  .x:hover { color: var(--text-strong); background: var(--color-paper-2); }
  .x:active { background: var(--color-paper-3); }
  .body { padding: var(--space-lg); }
  footer { display: flex; justify-content: flex-end; gap: var(--space-xs); padding: var(--space-sm) var(--space-lg) var(--space-md); border-top: var(--rule-hair) solid var(--border); background: var(--color-paper); flex-wrap: wrap; }
</style>
