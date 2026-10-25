<script lang="ts">
  import type { Snippet } from 'svelte';

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
      <button class="x" aria-label="Close" onclick={() => (open = false)}>×</button>
    </header>
    <div class="body">{@render children()}</div>
    {#if footer}<footer>{@render footer()}</footer>{/if}
  {/if}
</dialog>

<style>
  dialog {
    width: min(520px, calc(100vw - 32px));
    max-height: calc(100vh - 48px);
    padding: 0;
    border: 1px solid var(--border-strong);
    border-radius: 10px;
    background: var(--surface);
    color: var(--text);
    box-shadow: 0 16px 48px rgba(0, 0, 0, 0.5);
  }
  dialog.wide { width: min(820px, calc(100vw - 32px)); }
  dialog::backdrop { background: rgba(1, 4, 9, 0.7); }
  header { display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; border-bottom: 1px solid var(--border); }
  h2 { margin: 0; font-size: 16px; }
  .x { border: 0; background: none; font-size: 22px; line-height: 1; color: var(--muted); cursor: pointer; padding: 0 4px; }
  .x:hover { color: var(--text-strong); }
  .body { padding: 18px; }
  footer { display: flex; justify-content: flex-end; gap: 8px; padding: 12px 18px; border-top: 1px solid var(--border); flex-wrap: wrap; }
</style>
