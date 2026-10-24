<script lang="ts">
  import { onMount } from 'svelte';
  import { api, setUnauthorizedHandler, type Me } from './lib/api';
  import Login from './lib/Login.svelte';
  import ThreatFeed from './lib/ThreatFeed.svelte';

  let me = $state<Me | null>(null);
  let checking = $state(true);

  setUnauthorizedHandler(() => (me = null));

  onMount(async () => {
    try {
      me = await api<Me>('/api/auth/me');
    } catch {
      me = null;
    } finally {
      checking = false;
    }
  });

  async function logout() {
    await api('/api/auth/logout', { method: 'POST' }).catch(() => {});
    me = null;
  }
</script>

{#if checking}
  <div class="boot" aria-busy="true"></div>
{:else if !me}
  <Login onLogin={(user) => (me = user)} />
{:else}
  <header class="topbar">
    <a class="brand" href="/">
      <svg viewBox="0 0 16 16" width="18" height="18" aria-hidden="true"><path fill="currentColor" d="M8 0 1.5 2.5v5C1.5 11.6 4.3 15 8 16c3.7-1 6.5-4.4 6.5-8.5v-5Z" /></svg>
      SentinelVPS
    </a>
    <nav aria-label="Main">
      <a href="/" class="active" aria-current="page">Threat feed</a>
    </nav>
    <div class="user">
      <span class="who">{me.username}{me.readOnly ? ' (read-only)' : ''}</span>
      <button class="btn" onclick={logout}>Sign out</button>
    </div>
  </header>
  <main>
    <ThreatFeed />
  </main>
{/if}

<style>
  .boot { min-height: 100vh; }
  .topbar {
    position: sticky;
    top: 0;
    z-index: 10;
    display: flex;
    align-items: center;
    gap: 24px;
    padding: 10px 24px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--text-strong);
    font-weight: 600;
    font-size: 15px;
  }
  .brand svg { color: var(--link); }
  .brand:hover { text-decoration: none; }
  nav { display: flex; gap: 4px; flex: 1; }
  nav a {
    padding: 4px 10px;
    border-radius: var(--radius);
    color: var(--muted);
  }
  nav a.active { color: var(--text-strong); background: var(--surface-2); }
  nav a:hover { text-decoration: none; color: var(--text-strong); }
  .user { display: flex; align-items: center; gap: 12px; }
  .who { color: var(--muted); }
  main { max-width: 1040px; margin: 0 auto; padding: 24px; }
  @media (max-width: 640px) {
    .topbar { padding: 10px 16px; gap: 12px; }
    .who { display: none; }
    main { padding: 16px; }
  }
</style>
