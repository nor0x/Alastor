<script lang="ts">
  import { dismiss, toasts } from '../toast.svelte';
</script>

<div class="toasts" aria-live="polite">
  {#each toasts as t (t.id)}
    <div class="toast {t.kind}" role={t.kind === 'error' ? 'alert' : 'status'}>
      <span>{t.text}</span>
      <button aria-label="Dismiss" onclick={() => dismiss(t.id)}>×</button>
    </div>
  {/each}
</div>

<style>
  .toasts { position: fixed; right: 16px; bottom: 16px; z-index: 100; display: flex; flex-direction: column; gap: 8px; width: min(380px, calc(100vw - 32px)); }
  .toast {
    display: flex; justify-content: space-between; align-items: flex-start; gap: 10px;
    padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border-strong); border-left: 3px solid var(--info);
    background: var(--surface-2); box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  }
  .toast.ok { border-left-color: var(--ok); }
  .toast.error { border-left-color: var(--bad); }
  button { border: 0; background: none; color: var(--muted); cursor: pointer; font-size: 18px; line-height: 1; }
</style>
