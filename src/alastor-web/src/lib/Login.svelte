<script lang="ts">
  import { api, ApiError, type Me } from './api';
  import Icon from './ui/Icon.svelte';
  import BrandSpell from './ui/BrandSpell.svelte';

  let { onLogin }: { onLogin: (me: Me) => void } = $props();

  let username = $state('admin');
  let password = $state('');
  let error = $state('');
  let busy = $state(false);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      onLogin(await api<Me>('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }));
    } catch (err) {
      error = err instanceof ApiError && err.status === 429 ? 'Too many attempts. Wait a minute.' : err instanceof Error ? err.message : 'Sign-in failed.';
    } finally {
      busy = false;
    }
  }
</script>

<div class="wrap">
  <form onsubmit={submit}>
    <BrandSpell size={36} placement="inline">
      {#snippet label()}<h1>Alastor</h1>{/snippet}
    </BrandSpell>
    <label>Username <input class="field" bind:value={username} autocomplete="username" required /></label>
    <label>Password <input class="field" type="password" bind:value={password} autocomplete="current-password" required /></label>
    {#if error}<p class="error" role="alert"><Icon name="error" />{error}</p>{/if}
    <button class="btn primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
  </form>
</div>

<style>
  /* The ground: Cobalt's dot grid on the 8 by 16 cell, standing in for the ASCII field. */
  .wrap {
    min-height: 100dvh; display: grid; place-items: center; padding: var(--space-md);
    background-color: var(--color-paper);
    background-image: radial-gradient(circle at 1px 1px, var(--color-glyph-2) 1px, transparent 1.5px);
    background-size: var(--cell-w) var(--cell-h);
  }
  form {
    width: min(360px, 100%);
    display: flex; flex-direction: column; gap: var(--space-md);
    padding: var(--space-xl) var(--space-lg) var(--space-lg);
    background: var(--color-key-face); border: var(--rule-hair) solid var(--border); border-radius: var(--radius-card);
    box-shadow: var(--shadow-float);
  }
  @supports (corner-shape: bevel) { form { border-radius: var(--cut-l) 4px; corner-shape: bevel round; } }
  h1 { font-size: var(--text-2xl); }
  label { display: flex; flex-direction: column; gap: var(--space-2xs); font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--color-ink-2); }
  label .field { font-family: var(--font-body); font-weight: 400; font-size: var(--text-md); min-height: 40px; }
  .error { display: flex; gap: var(--space-xs); align-items: flex-start; color: var(--bad); }
  .error :global(svg) { margin-top: var(--space-3xs); }
  .btn { min-height: 40px; margin-top: var(--space-2xs); }
</style>
