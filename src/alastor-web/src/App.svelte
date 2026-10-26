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
  import Blocklists from './pages/Blocklists.svelte';
  import Baseline from './pages/Baseline.svelte';
  import Vulnerabilities from './pages/Vulnerabilities.svelte';
  import Policies from './pages/Policies.svelte';
  import PolicyEditor from './pages/PolicyEditor.svelte';
  import Settings from './pages/Settings.svelte';
  import About from './pages/About.svelte';
  import ThreatFeed from './lib/ThreatFeed.svelte';
  import Icon from './lib/ui/Icon.svelte';

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
    { href: '/', label: 'Overview', group: 'Fleet', match: (p: string) => p === '/' },
    { href: '/hosts', label: 'Hosts', group: 'Fleet', match: (p: string) => p.startsWith('/hosts') },
    { href: '/baseline', label: 'Baseline', group: 'Posture', match: (p: string) => p.startsWith('/baseline') },
    { href: '/vulnerabilities', label: 'CVEs', group: 'Posture', match: (p: string) => p.startsWith('/vulnerabilities') },
    { href: '/policies', label: 'Policies', group: 'Posture', match: (p: string) => p.startsWith('/policies') },
    { href: '/events', label: 'Events', group: 'Activity', match: (p: string) => p.startsWith('/events') },
    { href: '/bans', label: 'Bans', group: 'Activity', match: (p: string) => p.startsWith('/bans') || p.startsWith('/blocklists') },
    { href: '/feed', label: 'Threat feed', group: 'Activity', match: (p: string) => p.startsWith('/feed') },
    { href: '/settings', label: 'Settings', group: '', match: (p: string) => p.startsWith('/settings') },
  ];
  const navGroups = ['Fleet', 'Posture', 'Activity', ''].map((g) => ({ name: g, items: nav.filter((n) => n.group === g) }));

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
    if (p === '/blocklists') return { name: 'blocklists' } as const;
    if (p === '/baseline') return { name: 'baseline' } as const;
    if (p === '/vulnerabilities') return { name: 'vulnerabilities' } as const;
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

  const titles: Record<string, string> = { overview: 'Overview', hosts: 'Hosts', host: 'Host', events: 'Events', bans: 'Bans', blocklists: 'Blocklists', baseline: 'Security baseline', vulnerabilities: 'Vulnerabilities', policies: 'Policies', policy: 'Policy', feed: 'Threat feed', settings: 'Settings', about: 'About', notfound: 'Not found' };
  $effect(() => {
    document.title = `${titles[page.name]} · Alastor`;
  });
</script>

{#if checking}
  <div class="boot" aria-busy="true"></div>
{:else if !session.me}
  {#if page.name === 'about'}
    <main class="public"><About /><p class="back"><a href="/">Sign in</a></p></main>
  {:else}
    <Login onLogin={signedIn} />
  {/if}
{:else}
  <div class="shell">
    <aside class="side" class:open={menuOpen}>
      <div class="bar">
        <a class="brand" href="/" aria-label="Alastor overview">
          <Icon name="shield" size={20} />
          Alastor
        </a>
        <button class="menu-btn btn small" aria-expanded={menuOpen} aria-controls="main-nav" onclick={() => (menuOpen = !menuOpen)}>
          <Icon name={menuOpen ? 'close' : 'menu'} />Menu
        </button>
      </div>
      <nav id="main-nav" aria-label="Main">
        {#each navGroups as g (g.name)}
          <div class="group">
            {#if g.name}<span class="group-name">{g.name}</span>{/if}
            {#each g.items as item (item.href)}
              {@const active = item.match(route.path)}
              <a href={item.href} class:active aria-current={active ? 'page' : undefined}>{item.label}</a>
            {/each}
          </div>
        {/each}
      </nav>
      <div class="user">
        <span class="live" class:on={live.connected} title={live.connected ? 'Live updates connected' : 'Live updates unavailable; refreshing periodically'}>
          <span class="dot" class:ok={live.connected}></span>{live.connected ? 'Live' : 'Polling'}
        </span>
        <div class="who-row">
          <span class="who">{session.me.username}{session.me.readOnly ? ' (read-only)' : ''}</span>
          <button class="btn small" onclick={logout}>Sign out</button>
        </div>
        <div class="links"><a href="/about">About &amp; licenses</a><a href="/openapi/v1.json" target="_blank" rel="noopener">API</a></div>
      </div>
    </aside>
    <main>
      {#if page.name === 'overview'}<Overview />
      {:else if page.name === 'hosts'}<Hosts />
      {:else if page.name === 'host'}{#key page.id}<HostDetail id={page.id} />{/key}
      {:else if page.name === 'events'}<Events />
      {:else if page.name === 'bans'}<Bans />
      {:else if page.name === 'blocklists'}<Blocklists />
      {:else if page.name === 'baseline'}<Baseline />
      {:else if page.name === 'vulnerabilities'}<Vulnerabilities />
      {:else if page.name === 'policies'}<Policies />
      {:else if page.name === 'policy'}{#key `${page.scope}/${page.id}`}<PolicyEditor scope={page.scope} targetId={page.id} />{/key}
      {:else if page.name === 'feed'}<ThreatFeed />
      {:else if page.name === 'settings'}<Settings section={page.section} />
      {:else if page.name === 'about'}<About />
      {:else}
        <div class="empty empty-dashed">This page doesn’t exist. <a href="/">Go to the overview</a></div>
      {/if}
    </main>
  </div>
{/if}

<ConfirmHost />
<Toasts />

<style>
  .boot { min-height: 100dvh; }
  .shell { display: grid; grid-template-columns: var(--sidebar) minmax(0, 1fr); min-height: 100dvh; }
  .side {
    position: sticky; top: 0; z-index: var(--z-sticky-nav);
    display: flex; flex-direction: column; height: 100dvh;
    background: var(--color-paper-2); border-right: var(--rule-hair) solid var(--border);
  }
  .bar { display: flex; align-items: center; justify-content: space-between; gap: var(--space-sm); padding: var(--space-md) var(--space-md) var(--space-sm); }
  .brand { display: inline-flex; align-items: center; gap: var(--space-xs); color: var(--text-strong); font: 600 var(--text-xl)/1 var(--font-display); letter-spacing: var(--tracking-display); white-space: nowrap; }
  .brand :global(svg) { color: var(--color-accent); }
  .brand:hover { text-decoration: none; }
  .menu-btn { display: none; }
  nav { flex: 1; display: flex; flex-direction: column; gap: var(--space-md); padding: var(--space-xs) var(--space-sm); overflow-y: auto; }
  .group { display: flex; flex-direction: column; gap: var(--space-3xs); }
  .group-name { padding: 0 var(--space-sm) var(--space-2xs); font-family: var(--font-display); font-weight: 500; font-size: var(--text-xs); color: var(--muted); }
  nav a {
    display: flex; align-items: center; min-height: 36px; padding: 0 var(--space-sm);
    border: var(--rule-hair) solid transparent; border-radius: var(--radius-input);
    color: var(--color-ink-2); font-family: var(--font-display); font-weight: 500; font-size: var(--text-md); white-space: nowrap;
  }
  nav a:hover { text-decoration: none; color: var(--text-strong); background: var(--color-paper-3); }
  nav a:active { background: var(--color-rule); }
  nav a:focus-visible { outline-offset: -2px; }
  nav a.active { color: var(--color-accent-deep); background: var(--color-key-face); border-color: var(--border); box-shadow: var(--shadow-card); }
  .user { display: flex; flex-direction: column; gap: var(--space-xs); padding: var(--space-md); border-top: var(--rule-hair) solid var(--border); font-size: var(--text-sm); }
  .live { display: inline-flex; align-items: center; gap: var(--space-xs); color: var(--muted); }
  .live.on { color: var(--ok); }
  .who-row { display: flex; align-items: center; justify-content: space-between; gap: var(--space-xs); }
  .who { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-strong); font-family: var(--font-display); font-weight: 500; }
  .links { display: flex; flex-wrap: wrap; gap: var(--space-2xs) var(--space-sm); }
  .links a { color: var(--muted); }
  .links a:hover { color: var(--link); }
  main { width: 100%; max-width: var(--container); margin: 0 auto; padding: var(--space-xl) var(--gutter) var(--space-2xl); min-width: 0; }
  main.public { max-width: 1040px; }
  .back { margin-top: var(--space-lg); }

  @media (max-width: 60rem) {
    .shell { grid-template-columns: minmax(0, 1fr); }
    .side { height: auto; max-height: 100dvh; border-right: 0; border-bottom: var(--rule-hair) solid var(--border); }
    .bar { min-height: 56px; padding: var(--space-xs) var(--gutter); }
    .menu-btn { display: inline-flex; }
    nav, .user { display: none; }
    .side.open nav, .side.open .user { display: flex; }
    .side.open nav { flex: none; padding: var(--space-xs) var(--gutter) var(--space-md); }
    .side.open .user { padding: var(--space-md) var(--gutter); }
    nav a { min-height: 44px; }
    main { padding-top: var(--space-lg); }
  }
</style>
