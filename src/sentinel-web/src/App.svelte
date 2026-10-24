<script lang="ts">
  import { api, setUnauthorizedHandler, type Me } from './lib/api';
  import { match, route } from './lib/router.svelte';
  import { session } from './lib/session.svelte';
  import { live, startLive, stopLive } from './lib/live.svelte';
  import { refreshFleet, wireFleet } from './lib/fleet.svelte';
  import Login from './lib/Login.svelte';
  import ConfirmHost from './lib/ui/ConfirmHost.svelte';
  import Toasts from './lib/ui/Toasts.svelte';
  import Overview from './pages/Overview.svelte';
  import Hosts from './pages/Hosts.svelte';
  import HostDetail from './pages/HostDetail.svelte';
  import Events from './pages/Events.svelte';
  import Bans from './pages/Bans.svelte';
  import Policies from './pages/Policies.svelte';
  import PolicyEditor from './pages/PolicyEditor.svelte';
  import Settings from './pages/Settings.svelte';
  import About from './pages/About.svelte';
  import ThreatFeed from './lib/ThreatFeed.svelte';

  let checking = $state(true);
  let menuOpen = $state(false);

  setUnauthorizedHandler(() => signedOut());

  $effect(() => {
    api<Me>('/api/auth/me')
      .then(signedIn)
      .catch(() => (session.me = null))
      .finally(() => (checking = false));
  });

  function signedIn(me: Me) {
    session.me = me;
    wireFleet();
    startLive();
    refreshFleet();
  }

  function signedOut() {
    session.me = null;
    stopLive();
  }

  async function logout() {
    await api('/api/auth/logout', { method: 'POST' }).catch(() => {});
    signedOut();
  }

  const nav = [
    { href: '/', label: 'Overview', match: (p: string) => p === '/' },
    { href: '/hosts', label: 'Hosts', match: (p: string) => p.startsWith('/hosts') },
    { href: '/events', label: 'Events', match: (p: string) => p.startsWith('/events') },
    { href: '/bans', label: 'Bans', match: (p: string) => p.startsWith('/bans') },
    { href: '/policies', label: 'Policies', match: (p: string) => p.startsWith('/policies') },
    { href: '/feed', label: 'Threat feed', match: (p: string) => p.startsWith('/feed') },
    { href: '/settings', label: 'Settings', match: (p: string) => p.startsWith('/settings') },
  ];

  // Close the mobile menu after navigating.
  $effect(() => {
    void route.path;
    menuOpen = false;
  });

  const page = $derived.by(() => {
    const p = route.path.replace(/\/+$/, '') || '/';
    let m: Record<string, string> | null;
    if (p === '/') return { name: 'overview' } as const;
    if (p === '/hosts') return { name: 'hosts' } as const;
    if ((m = match('/hosts/:id', p))) return { name: 'host', id: m.id } as const;
    if (p === '/events') return { name: 'events' } as const;
    if (p === '/bans') return { name: 'bans' } as const;
    if (p === '/policies') return { name: 'policies' } as const;
    if (p === '/policies/global') return { name: 'policy', scope: 'global', id: null } as const;
    if ((m = match('/policies/group/:id', p))) return { name: 'policy', scope: 'group', id: m.id } as const;
    if ((m = match('/policies/host/:id', p))) return { name: 'policy', scope: 'host', id: m.id } as const;
    if (p === '/feed') return { name: 'feed' } as const;
    if (p === '/settings') return { name: 'settings', section: 'groups' } as const;
    if ((m = match('/settings/:section', p))) return { name: 'settings', section: m.section } as const;
    if (p === '/about') return { name: 'about' } as const;
    return { name: 'notfound' } as const;
  });

  const titles: Record<string, string> = { overview: 'Overview', hosts: 'Hosts', host: 'Host', events: 'Events', bans: 'Bans', policies: 'Policies', policy: 'Policy', feed: 'Threat feed', settings: 'Settings', about: 'About', notfound: 'Not found' };
  $effect(() => {
    document.title = `${titles[page.name]} · SentinelVPS`;
  });
</script>

{#if checking}
  <div class="boot" aria-busy="true"></div>
{:else if !session.me}
  {#if page.name === 'about'}
    <main class="public"><About /><p><a href="/">← Sign in</a></p></main>
  {:else}
    <Login onLogin={signedIn} />
  {/if}
{:else}
  <header class="topbar">
    <a class="brand" href="/">
      <svg viewBox="0 0 16 16" width="18" height="18" aria-hidden="true"><path fill="currentColor" d="M8 0 1.5 2.5v5C1.5 11.6 4.3 15 8 16c3.7-1 6.5-4.4 6.5-8.5v-5Z" /></svg>
      SentinelVPS
    </a>
    <button class="menu-btn btn" aria-expanded={menuOpen} aria-controls="main-nav" onclick={() => (menuOpen = !menuOpen)}>Menu</button>
    <nav id="main-nav" aria-label="Main" class:open={menuOpen}>
      {#each nav as item (item.href)}
        {@const active = item.match(route.path)}
        <a href={item.href} class:active aria-current={active ? 'page' : undefined}>{item.label}</a>
      {/each}
    </nav>
    <div class="user">
      <span class="live" class:on={live.connected} title={live.connected ? 'Live updates connected' : 'Live updates unavailable; refreshing periodically'}>
        <span class="dot" class:ok={live.connected}></span>{live.connected ? 'Live' : 'Polling'}
      </span>
      <span class="who">{session.me.username}{session.me.readOnly ? ' (read-only)' : ''}</span>
      <button class="btn" onclick={logout}>Sign out</button>
    </div>
  </header>
  <main>
    {#if page.name === 'overview'}<Overview />
    {:else if page.name === 'hosts'}<Hosts />
    {:else if page.name === 'host'}{#key page.id}<HostDetail id={page.id} />{/key}
    {:else if page.name === 'events'}<Events />
    {:else if page.name === 'bans'}<Bans />
    {:else if page.name === 'policies'}<Policies />
    {:else if page.name === 'policy'}{#key `${page.scope}/${page.id}`}<PolicyEditor scope={page.scope} targetId={page.id} />{/key}
    {:else if page.name === 'feed'}<ThreatFeed />
    {:else if page.name === 'settings'}<Settings section={page.section} />
    {:else if page.name === 'about'}<About />
    {:else}
      <div class="empty empty-dashed">This page doesn't exist. <a href="/">Go to the overview</a></div>
    {/if}
  </main>
  <footer class="foot"><a href="/about">About &amp; licenses</a> · <a href="/openapi/v1.json" target="_blank" rel="noopener">API</a></footer>
{/if}

<ConfirmHost />
<Toasts />

<style>
  .boot { min-height: 100vh; }
  .topbar {
    position: sticky; top: 0; z-index: 10;
    display: flex; align-items: center; gap: 20px;
    padding: 10px 24px;
    background: var(--surface); border-bottom: 1px solid var(--border);
  }
  .brand { display: flex; align-items: center; gap: 8px; color: var(--text-strong); font-weight: 600; font-size: 15px; white-space: nowrap; }
  .brand svg { color: var(--link); }
  .brand:hover { text-decoration: none; }
  nav { display: flex; gap: 2px; flex: 1; overflow-x: auto; }
  nav a { padding: 4px 10px; border-radius: var(--radius); color: var(--muted); white-space: nowrap; }
  nav a.active { color: var(--text-strong); background: var(--surface-2); }
  nav a:hover { text-decoration: none; color: var(--text-strong); }
  .menu-btn { display: none; }
  .user { display: flex; align-items: center; gap: 12px; }
  .who { color: var(--muted); white-space: nowrap; }
  .live { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--muted); }
  main { max-width: 1240px; margin: 0 auto; padding: 24px; }
  main.public { max-width: 1040px; }
  .foot { max-width: 1240px; margin: 0 auto; padding: 8px 24px 32px; color: var(--muted); font-size: 12px; }
  @media (max-width: 980px) {
    .topbar { flex-wrap: wrap; padding: 10px 16px; gap: 10px; }
    .menu-btn { display: inline-flex; margin-left: auto; }
    nav { display: none; order: 10; flex-basis: 100%; flex-direction: column; }
    nav.open { display: flex; }
    nav a { padding: 8px 10px; }
    .user { gap: 8px; }
    .who { display: none; }
    main { padding: 16px; }
    .foot { padding: 8px 16px 24px; }
  }
</style>
