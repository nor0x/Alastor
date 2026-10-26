<script lang="ts">
  import { api, ApiError, type LoginResult, type Me } from './api';
  import Icon from './ui/Icon.svelte';
  import BrandSpell from './ui/BrandSpell.svelte';

  let { onLogin }: { onLogin: (me: Me) => void } = $props();

  let username = $state('admin');
  let password = $state('');
  let error = $state('');
  let busy = $state(false);
  // Second step, only for users who turned on two-factor sign-in.
  let secondStep = $state(false);
  let useRecovery = $state(false);
  let code = $state('');

  const message = (err: unknown) =>
    err instanceof ApiError && err.status === 429 ? 'Too many attempts. Wait a minute.' : err instanceof Error ? err.message : 'Sign-in failed.';

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      const r = await api<LoginResult>('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
      if (r.twoFactorRequired) {
        secondStep = true;
        password = '';
      } else onLogin(r as Me);
    } catch (err) {
      error = message(err);
    } finally {
      busy = false;
    }
  }

  async function submitCode(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      const body = useRecovery ? { recoveryCode: code } : { code };
      onLogin(await api<Me>('/api/auth/login/2fa', { method: 'POST', body: JSON.stringify(body) }));
    } catch (err) {
      error = message(err);
      if (err instanceof ApiError && err.status === 401 && /again/.test(error)) secondStep = false;
    } finally {
      busy = false;
    }
  }
</script>

<div class="wrap">
  {#if !secondStep}
    <form onsubmit={submit}>
      <BrandSpell size={36} placement="inline">
        {#snippet label()}<h1>Alastor</h1>{/snippet}
      </BrandSpell>
      <label>Username <input class="field" bind:value={username} autocomplete="username" required /></label>
      <label>Password <input class="field" type="password" bind:value={password} autocomplete="current-password" required /></label>
      {#if error}<p class="error" role="alert"><Icon name="error" />{error}</p>{/if}
      <button class="btn primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
    </form>
  {:else}
    <form onsubmit={submitCode}>
      <BrandSpell size={36} placement="inline">
        {#snippet label()}<h1>Alastor</h1>{/snippet}
      </BrandSpell>
      {#if useRecovery}
        <label>Recovery code <input class="field mono" bind:value={code} autocomplete="off" placeholder="xxxxx-xxxxx" required /></label>
      {:else}
        <label>Code from your authenticator app
          <!-- svelte-ignore a11y_autofocus -->
          <input class="field mono" bind:value={code} inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{'{6,7}'}" maxlength="7" required autofocus />
        </label>
      {/if}
      {#if error}<p class="error" role="alert"><Icon name="error" />{error}</p>{/if}
      <button class="btn primary" disabled={busy}>{busy ? 'Checking…' : 'Sign in'}</button>
      <button type="button" class="link" onclick={() => { useRecovery = !useRecovery; code = ''; error = ''; }}>
        {useRecovery ? 'Use a code from the app' : 'Lost your phone? Use a recovery code'}
      </button>
    </form>
  {/if}
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
  label .field.mono { font-family: var(--mono); letter-spacing: 0.08em; }
  .link { align-self: center; background: none; border: 0; padding: var(--space-2xs); color: var(--color-ink-2); font-size: var(--text-sm); text-decoration: underline; cursor: pointer; }
  .link:hover { color: var(--text-strong); }
</style>
