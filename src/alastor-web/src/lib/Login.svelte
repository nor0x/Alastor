<script lang="ts">
  import { api, ApiError, type Me } from './api';

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
    <h1>
      <svg viewBox="0 0 16 16" width="22" height="22" aria-hidden="true"><path fill="currentColor" d="M8 0 1.5 2.5v5C1.5 11.6 4.3 15 8 16c3.7-1 6.5-4.4 6.5-8.5v-5Z" /></svg>
      Alastor
    </h1>
    <label>Username <input class="field" bind:value={username} autocomplete="username" required /></label>
    <label>Password <input class="field" type="password" bind:value={password} autocomplete="current-password" required /></label>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    <button class="btn primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
  </form>
</div>

<style>
  .wrap { min-height: 100vh; display: grid; place-items: center; padding: 16px; }
  form {
    width: min(340px, 100%);
    display: flex;
    flex-direction: column;
    gap: 14px;
    padding: 28px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
  }
  h1 { display: flex; align-items: center; gap: 8px; margin: 0 0 6px; font-size: 20px; color: var(--text-strong); }
  h1 svg { color: var(--link); }
  label { display: flex; flex-direction: column; gap: 6px; color: var(--muted); font-size: 13px; }
  .error { margin: 0; color: var(--sev-critical); }
  .btn { justify-content: center; padding: 7px 12px; }
</style>
