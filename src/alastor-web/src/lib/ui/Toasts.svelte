<script lang="ts">
  import { dismiss, toasts } from '../toast.svelte';
  import Icon from './Icon.svelte';
</script>

<div class="toasts" aria-live="polite">
  {#each toasts as t (t.id)}
    <div class="toast {t.kind}" role={t.kind === 'error' ? 'alert' : 'status'}>
      <Icon name={t.kind === 'error' ? 'error' : t.kind === 'ok' ? 'check' : 'info'} />
      <span class="text">{t.text}</span>
      <button aria-label="Dismiss" onclick={() => dismiss(t.id)}><Icon name="close" /></button>
    </div>
  {/each}
</div>

<style>
  /* Toasts run on graphite, like the code panels. */
  .toasts { position: fixed; right: var(--space-md); bottom: var(--space-md); z-index: var(--z-toast); display: flex; flex-direction: column; gap: var(--space-xs); width: 380px; max-width: calc(100% - 2 * var(--space-md)); }
  .toast {
    display: flex; align-items: flex-start; gap: var(--space-sm);
    padding: var(--space-sm) var(--space-sm) var(--space-sm) var(--space-md); border-radius: var(--radius-input);
    background: var(--color-graphite); color: var(--color-graphite-ink); box-shadow: var(--shadow-float);
  }
  @supports (corner-shape: bevel) { .toast { border-radius: var(--cut) 2px; corner-shape: bevel round; } }
  .toast > :global(svg) { margin-top: var(--space-3xs); color: var(--color-accent-2); }
  .toast.ok > :global(svg) { color: var(--color-graphite-success); }
  .toast.error > :global(svg) { color: var(--color-graphite-error); }
  .text { flex: 1; min-width: 0; }
  button { display: inline-grid; place-items: center; width: 24px; height: 24px; border: 0; border-radius: 4px; background: none; color: var(--color-graphite-muted); cursor: pointer; }
  button:hover { color: var(--color-graphite-ink); background: var(--color-graphite-2); }
  button:focus-visible { outline-color: var(--color-accent-2); }
</style>
