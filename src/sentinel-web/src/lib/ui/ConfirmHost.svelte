<script lang="ts">
  import Modal from './Modal.svelte';
  import { pendingConfirm } from './confirm.svelte';

  let open = $state(false);
  const req = $derived(pendingConfirm.current);

  $effect(() => {
    open = !!req;
  });

  // Closing by Escape or the backdrop counts as "cancel".
  $effect(() => {
    if (!open && pendingConfirm.current) finish(false);
  });

  function finish(ok: boolean) {
    const r = pendingConfirm.current;
    pendingConfirm.current = null;
    r?.resolve(ok);
  }
</script>

<Modal bind:open title={req?.title ?? ''}>
  <p class="msg">{req?.message}</p>
  {#snippet footer()}
    <button class="btn" onclick={() => finish(false)}>Cancel</button>
    <button class="btn {req?.danger ? 'solid-danger' : 'primary'}" onclick={() => finish(true)}>{req?.confirmLabel ?? 'Confirm'}</button>
  {/snippet}
</Modal>

<style>
  .msg { margin: 0; white-space: pre-line; }
</style>
