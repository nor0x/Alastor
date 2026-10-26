<script lang="ts">
  import { api, errorText } from '../../lib/api';
  import { session } from '../../lib/session.svelte';
  import { toast } from '../../lib/toast.svelte';
  import Icon from '../../lib/ui/Icon.svelte';

  let current = $state('');
  let next = $state('');
  let repeat = $state('');
  let error = $state('');
  let busy = $state(false);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    if (next.length < 12) return void (error = 'Use at least 12 characters.');
    if (next !== repeat) return void (error = "The new passwords don't match.");
    busy = true;
    try {
      await api('/api/auth/password', { method: 'POST', body: JSON.stringify({ currentPassword: current, newPassword: next }) });
      current = next = repeat = '';
      toast('Password changed.');
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }
</script>

<section class="card">
  <header><h2>Change password</h2><span class="hint">signed in as {session.me?.username}</span></header>
  <form class="card-body form narrow" onsubmit={submit}>
    <label>Current password <input class="field" type="password" bind:value={current} autocomplete="current-password" required /></label>
    <label>New password <input class="field" type="password" bind:value={next} autocomplete="new-password" minlength="12" required /></label>
    <label>Repeat new password <input class="field" type="password" bind:value={repeat} autocomplete="new-password" required /></label>
    {#if error}<div class="banner bad" role="alert"><Icon name="error" /><p>{error}</p></div>{/if}
    <div class="form-actions"><button class="btn primary" disabled={busy}>Change password</button></div>
  </form>
</section>

<style>
  .narrow { max-width: 420px; }
  .banner > :global(.icon) { margin-top: var(--space-3xs); color: var(--bad); }
</style>
