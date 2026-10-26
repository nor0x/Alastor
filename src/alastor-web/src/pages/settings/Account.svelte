<script lang="ts">
  import qrcode from 'qrcode-generator';
  import { api, errorText, type UserSession } from '../../lib/api';
  import { session } from '../../lib/session.svelte';
  import { toast } from '../../lib/toast.svelte';
  import { confirm } from '../../lib/ui/confirm.svelte';
  import CopyButton from '../../lib/ui/CopyButton.svelte';
  import Icon from '../../lib/ui/Icon.svelte';
  import Time from '../../lib/ui/Time.svelte';

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
      toast('Password changed. Other browsers were signed out.');
      loadSessions();
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }

  // ---- two-factor sign-in (optional) ----

  let setup = $state<{ secret: string; uri: string } | null>(null);
  let setupCode = $state('');
  let recovery = $state<string[] | null>(null);
  let offPassword = $state('');
  let offCode = $state('');
  let tfaError = $state('');

  const qr = $derived.by(() => {
    if (!setup) return '';
    const q = qrcode(0, 'M');
    q.addData(setup.uri);
    q.make();
    return q.createDataURL(5, 2);
  });

  async function startSetup() {
    tfaError = '';
    try {
      setup = await api('/api/auth/2fa/setup', { method: 'POST' });
    } catch (err) {
      toast(errorText(err), 'error');
    }
  }

  async function enable(e: SubmitEvent) {
    e.preventDefault();
    tfaError = '';
    try {
      const r = await api<{ recoveryCodes: string[] }>('/api/auth/2fa/enable', { method: 'POST', body: JSON.stringify({ code: setupCode }) });
      recovery = r.recoveryCodes;
      setup = null;
      setupCode = '';
      if (session.me) session.me.twoFactor = true;
      loadSessions();
    } catch (err) {
      tfaError = errorText(err);
    }
  }

  async function disable(e: SubmitEvent) {
    e.preventDefault();
    tfaError = '';
    try {
      await api('/api/auth/2fa/disable', { method: 'POST', body: JSON.stringify({ password: offPassword, code: offCode }) });
      offPassword = offCode = '';
      recovery = null;
      if (session.me) session.me.twoFactor = false;
      toast('Two-factor sign-in is off.');
    } catch (err) {
      tfaError = errorText(err);
    }
  }

  // ---- signed-in browsers ----

  let sessions = $state<UserSession[]>([]);
  const loadSessions = async () => (sessions = await api<UserSession[]>('/api/auth/sessions').catch(() => sessions));
  $effect(() => {
    loadSessions();
  });

  async function revoke(s: UserSession) {
    if (!(await confirm('Sign out this browser?', `${browser(s.userAgent)} at ${s.address ?? 'an unknown address'} has to sign in again.`, { confirmLabel: 'Sign out', danger: true }))) return;
    try {
      await api(`/api/auth/sessions/${s.id}`, { method: 'DELETE' });
      loadSessions();
    } catch (err) {
      toast(errorText(err), 'error');
    }
  }

  function browser(ua: string | null): string {
    if (!ua) return 'Unknown browser';
    const name = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl\//.test(ua) ? 'curl' : 'Browser';
    const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : '';
    return os ? `${name} on ${os}` : name;
  }
</script>

<div class="stack">
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

  <section class="card">
    <header><h2>Two-factor sign-in</h2><span class="hint">optional</span></header>
    <div class="card-body stack">
      {#if recovery}
        <div class="banner ok"><Icon name="check" /><p><strong>Two-factor sign-in is on.</strong> Save these recovery codes somewhere safe: each one signs you in once if you lose your phone. They aren't shown again.</p></div>
        <div class="codes mono">{#each recovery as c (c)}<span>{c}</span>{/each}</div>
        <div><CopyButton text={recovery.join('\n')} label="Copy codes" /></div>
      {:else if session.me?.twoFactor}
        <p class="muted small m0">On. Signing in asks for a code from your authenticator app after the password. To turn it off, confirm with your password and a current code (or a recovery code).</p>
        <form class="form narrow" onsubmit={disable}>
          <label>Password <input class="field" type="password" bind:value={offPassword} autocomplete="current-password" required /></label>
          <label>Code <input class="field" bind:value={offCode} autocomplete="one-time-code" required /></label>
          {#if tfaError}<div class="banner bad" role="alert"><Icon name="error" /><p>{tfaError}</p></div>{/if}
          <div class="form-actions"><button class="btn danger">Turn off</button></div>
        </form>
      {:else if setup}
        <div class="setup">
          <img src={qr} alt="QR code for your authenticator app" width="190" height="190" />
          <form class="form" onsubmit={enable}>
            <p class="muted small m0">Scan the code with an authenticator app (1Password, Bitwarden, Aegis, Google Authenticator, …), or enter the key by hand:</p>
            <div class="cmd"><code>{setup.secret}</code><CopyButton text={setup.secret} /></div>
            <label>Code the app shows <input class="field" bind:value={setupCode} inputmode="numeric" autocomplete="one-time-code" maxlength="7" required /></label>
            {#if tfaError}<div class="banner bad" role="alert"><Icon name="error" /><p>{tfaError}</p></div>{/if}
            <div class="form-actions"><button class="btn primary">Turn on</button><button type="button" class="btn" onclick={() => (setup = null)}>Cancel</button></div>
          </form>
        </div>
      {:else}
        <p class="muted small m0">Off. You can ask for a code from an authenticator app after the password, so a leaked password alone can't sign anyone in. It's up to you; nothing requires it.</p>
        <div><button class="btn" onclick={startSetup}>Set up two-factor sign-in</button></div>
      {/if}
    </div>
  </section>

  <section class="card">
    <header><h2>Signed-in browsers</h2><span class="hint">{sessions.length}</span></header>
    {#if sessions.length}
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Browser</th><th>Address</th><th class="hide-sm">Signed in</th><th>Last active</th><th></th></tr></thead>
          <tbody>
            {#each sessions as s (s.id)}
              <tr>
                <td>{browser(s.userAgent)} {#if s.current}<span class="pill">this browser</span>{/if}</td>
                <td class="mono">{s.address ?? '—'}</td>
                <td class="hide-sm nowrap"><Time iso={s.createdAt} /></td>
                <td class="nowrap"><Time iso={s.lastSeenAt} /></td>
                <td class="actions">{#if !s.current}<button class="btn small danger" onclick={() => revoke(s)}>Sign out</button>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
</div>

<style>
  .narrow { max-width: 420px; }
  .m0 { margin: 0; max-width: 75ch; }
  .banner > :global(.icon) { margin-top: var(--space-3xs); }
  .banner.bad > :global(.icon) { color: var(--bad); }
  .banner.ok > :global(.icon) { color: var(--ok); }
  .setup { display: flex; gap: var(--space-lg); align-items: flex-start; flex-wrap: wrap; }
  .setup img { image-rendering: pixelated; border-radius: var(--radius-input); background: #fff; flex: none; }
  .setup form { flex: 1 1 260px; max-width: 460px; }
  .codes { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: var(--space-2xs) var(--space-md); max-width: 560px; }
</style>
