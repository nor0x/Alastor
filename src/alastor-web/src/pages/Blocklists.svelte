<script lang="ts">
  import { api, errorText, type BlocklistLookup, type BlocklistOverview, type HostBlocklist, type PolicyLayerDetail } from '../lib/api';
  import { setLayerKey } from '../lib/baseline';
  import { number } from '../lib/format';
  import { refreshOn } from '../lib/live.svelte';
  import { canWrite } from '../lib/session.svelte';
  import { toast } from '../lib/toast.svelte';
  import Icon from '../lib/ui/Icon.svelte';
  import Time from '../lib/ui/Time.svelte';
  import { parseDocument } from 'yaml';

  let data = $state<BlocklistOverview | null>(null);
  let global = $state<{ enabled: boolean; lists: string[]; extra: string[] }>({ enabled: false, lists: [], extra: [] });
  let error = $state('');
  let busy = $state(false);
  let refreshing = $state<string | null>(null);

  async function load() {
    try {
      const [overview, layer] = await Promise.all([api<BlocklistOverview>('/api/blocklists'), api<PolicyLayerDetail>('/api/policies/global')]);
      const bl = (parseDocument(layer.yaml || '{}').toJS() ?? {}).blocklists ?? {};
      global = { enabled: bl.enabled === true, lists: Array.isArray(bl.lists) ? bl.lists : [], extra: Array.isArray(bl.extra) ? bl.extra.map(String) : [] };
      data = overview;
      error = '';
    } catch (e) {
      error = errorText(e);
    }
  }
  $effect(() => {
    load();
  });
  $effect(() => refreshOn(['policyChanged', 'hostUpdated'], load, 30_000));

  async function save(path: string[], value: boolean | string[], comment: string, done: string) {
    busy = true;
    try {
      await setLayerKey({ scope: 'global' }, ['blocklists', ...path], value, comment);
      toast(done);
      await load();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      busy = false;
    }
  }

  const toggleEnabled = () =>
    save(['enabled'], !global.enabled, global.enabled ? 'Turn off blocklists' : 'Turn on blocklists',
      global.enabled ? 'Blocklists turned off. Agents remove their table within a minute.' : 'Blocklists turned on. Agents load the set within a minute.');

  async function toggleList(id: string, name: string) {
    const on = global.lists.includes(id);
    const lists = on ? global.lists.filter((l) => l !== id) : [...global.lists, id];
    await save(['lists'], lists, `${on ? 'Remove' : 'Add'} blocklist ${id}`,
      on ? `${name} removed from the fleet's blocklists.` : `${name} added. The server fetches it now; agents load it on their next refresh.`);
    if (!on) await refresh(id, true);
  }

  async function refresh(id: string, quiet = false) {
    refreshing = id;
    try {
      const r = await api<{ success: boolean; error: string | null; entries: number }>(`/api/blocklists/${id}/refresh`, { method: 'POST' });
      if (!r.success) toast(`Fetching ${id} failed: ${r.error}`, 'error');
      else if (!quiet) toast(`${id}: ${number.format(r.entries)} networks.`);
      await load();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      refreshing = null;
    }
  }

  // ---- own entries ----
  let entry = $state('');
  async function addExtra(e: SubmitEvent) {
    e.preventDefault();
    const v = entry.trim();
    if (!v || global.extra.includes(v)) return;
    await save(['extra'], [...global.extra, v], `Block ${v}`, `${v} is blocked on every host with blocklists on.`);
    entry = '';
  }
  const removeExtra = (v: string) => save(['extra'], global.extra.filter((x) => x !== v), `Unblock ${v}`, `${v} removed.`);

  // ---- lookup ----
  let ip = $state('');
  let lookup = $state<BlocklistLookup | null>(null);
  let lookupError = $state('');
  async function check(e: SubmitEvent) {
    e.preventDefault();
    lookupError = '';
    lookup = null;
    try {
      lookup = await api<BlocklistLookup>(`/api/blocklists/lookup?ip=${encodeURIComponent(ip.trim())}`);
    } catch (err) {
      lookupError = errorText(err);
    }
  }

  function hostState(h: HostBlocklist): { label: string; tone: string } {
    if (!h.wanted) return h.active ? { label: 'removing', tone: 'warn' } : { label: 'off', tone: 'muted' };
    if (h.active) return { label: 'active', tone: 'ok' };
    if (h.configState === 'Rejected') return { label: 'refused', tone: 'bad' };
    return { label: h.online ? 'pending' : 'offline', tone: 'warn' };
  }

  const nameOf = (id: string) => data?.lists.find((l) => l.id === id)?.name ?? id;
  const totalDropped = $derived(data?.hosts.reduce((sum, h) => sum + (h.dropped ?? 0), 0) ?? 0);
  const activeHosts = $derived(data?.hosts.filter((h) => h.active).length ?? 0);
  const millions = (n: number) => (n >= 1e6 ? `${(n / 1e6).toFixed(n >= 1e8 ? 0 : 1)}M` : number.format(n));
</script>

<div class="page-head">
  <div>
    <h1>Bans</h1>
    <p class="sub">Public lists of known-bad networks. This server downloads them, merges them per host and takes out the allowlist; each agent drops matching traffic in the kernel.</p>
  </div>
</div>

<nav class="tabs" aria-label="Bans sections"><a href="/bans">Bans &amp; allowlist</a><a href="/blocklists" class="on" aria-current="page">Blocklists</a></nav>

{#if error}<div class="banner bad" role="alert"><p>{error}</p></div>{/if}

{#if data}
  {#if !data.fetchingEnabled}
    <div class="banner warn"><p>List downloads are turned off on this server (<code>ALASTOR_BLOCKLISTSENABLED=false</code>). Agents still block your own entries.</p></div>
  {/if}

  <section class="card fleet">
    <div class="card-body fleet-row">
      <div class="fleet-text">
        <h2>Fleet default <span class="pill {global.enabled ? 'ok' : 'muted'}">{global.enabled ? 'on' : 'off'}</span></h2>
        <p class="muted small">
          Set in the <a href="/policies/global">global policy</a>; groups and hosts can override <code>blocklists.enabled</code> and <code>blocklists.lists</code> in their own policy.
          {#if activeHosts}Active on {activeHosts} host{activeHosts === 1 ? '' : 's'}{#if totalDropped}, {number.format(totalDropped)} packets dropped since the sets were last loaded{/if}.{/if}
        </p>
      </div>
      {#if canWrite()}
        <button class="btn {global.enabled ? '' : 'primary'}" disabled={busy} onclick={toggleEnabled}>{global.enabled ? 'Turn off' : 'Turn on'}</button>
      {/if}
    </div>
  </section>

  <section class="card table-wrap">
    <header><h2>Lists</h2><span class="hint">refreshed every {data.refreshInterval} while in use</span></header>
    <table class="table lists">
      <thead><tr><th class="pick">Fleet</th><th>List</th><th class="num">Networks</th><th class="hide-sm">Updated</th><th>Status</th><th></th></tr></thead>
      <tbody>
        {#each data.lists as l (l.id)}
          {@const on = global.lists.includes(l.id)}
          <tr class:off={!on && !l.usedBy.length}>
            <td class="pick">
              <input type="checkbox" checked={on} disabled={!canWrite() || busy} onchange={() => toggleList(l.id, l.name)} aria-label="Use {l.name} on the fleet" />
            </td>
            <td class="desc">
              <a href={l.homepage} target="_blank" rel="noopener noreferrer"><strong>{l.name}</strong></a>
              <div class="muted small">{l.description}</div>
              <div class="meta muted small">
                <span>{l.terms}</span>
                {#if l.usedBy.length}<span>used by {l.usedBy.join(', ')}</span>{/if}
              </div>
            </td>
            <td class="num nowrap">
              {#if l.lastSuccessAt}{number.format(l.entries)}{#if l.ipv4Addresses}<div class="muted small">{millions(l.ipv4Addresses)} IPv4 addr.</div>{/if}{:else}<span class="nil" aria-label="none"></span>{/if}
            </td>
            <td class="hide-sm nowrap">{#if l.lastChangedAt}<Time iso={l.lastChangedAt} />{:else}<span class="muted">never</span>{/if}</td>
            <td class="status">
              {#if l.lastError}<span class="pill bad" title={l.lastError}>failing</span><div class="err small">{l.lastError}</div>
              {:else if l.lastSuccessAt}<span class="pill ok">ok</span><div class="muted small">checked <Time iso={l.lastSuccessAt} /></div>
              {:else if l.usedBy.length}<span class="pill warn">not fetched</span>
              {:else}<span class="muted small">not in use</span>{/if}
            </td>
            <td class="actions">
              {#if canWrite() && (on || l.usedBy.length)}
                <button class="btn small" disabled={refreshing === l.id} onclick={() => refresh(l.id)}>{refreshing === l.id ? 'Fetching…' : 'Fetch now'}</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>

  <div class="grid-2">
    <section class="card">
      <header><h2>Your own entries</h2><span class="hint">global policy</span></header>
      <div class="card-body stack">
        <p class="muted small m0">Networks you want dropped on every host that has blocklists on, on top of the lists. Private and reserved ranges are never blocked.</p>
        {#if global.extra.length}
          <ul class="chips">
            {#each global.extra as v (v)}
              <li class="mono">{v}{#if canWrite()}<button class="x" aria-label="Remove {v}" disabled={busy} onclick={() => removeExtra(v)}><Icon name="close" size={14} /></button>{/if}</li>
            {/each}
          </ul>
        {/if}
        {#if canWrite()}
          <form class="inline" onsubmit={addExtra}>
            <input class="field mono" bind:value={entry} placeholder="203.0.113.0/24" aria-label="IP or CIDR to block" required />
            <button class="btn" disabled={busy}>Block</button>
          </form>
        {/if}
      </div>
    </section>

    <section class="card">
      <header><h2>Look up an address</h2></header>
      <div class="card-body stack">
        <form class="inline" onsubmit={check}>
          <input class="field mono" bind:value={ip} placeholder="1.10.16.1" aria-label="IP address" required />
          <button class="btn">Check</button>
        </form>
        {#if lookupError}<p class="err small m0" role="alert">{lookupError}</p>{/if}
        {#if lookup}
          <div class="banner {lookup.lists.length || lookup.extra.length ? (lookup.allowlisted || lookup.reserved ? 'info' : 'warn') : 'ok'}">
            <p>
              <span class="mono">{lookup.target}</span>
              {#if lookup.lists.length || lookup.extra.length}
                is on {[...lookup.lists.map(nameOf), ...lookup.extra.map((e) => `your entry ${e}`)].join(', ')}.
              {:else}
                is on no downloaded list.
              {/if}
              {#if lookup.allowlisted} It's allowlisted, so it is never blocked.{/if}
              {#if lookup.reserved} It's a private or reserved address, so it is never blocked.{/if}
            </p>
          </div>
        {/if}
      </div>
    </section>
  </div>

  <section class="card table-wrap">
    <header><h2>Hosts</h2><span class="hint">as reported by each agent</span></header>
    {#if data.hosts.length}
      <table class="table">
        <thead><tr><th>Host</th><th>State</th><th class="hide-sm">Backend</th><th>Networks</th><th class="num">Dropped</th><th class="hide-sm">Loaded</th></tr></thead>
        <tbody>
          {#each data.hosts as h (h.hostId)}
            {@const st = hostState(h)}
            <tr>
              <td><a href="/hosts/{h.hostId}">{h.name}</a></td>
              <td>
                <span class="pill {st.tone}">{st.label}</span>
              </td>
              <td class="hide-sm">{#if h.backend}{h.backend}{:else}<span class="nil" aria-label="none"></span>{/if}</td>
              <td class="nowrap">{#if h.active && h.entries != null}{h.entries}{:else}<span class="nil" aria-label="none"></span>{/if}{#if h.active && h.lists}<div class="muted small">{h.lists}</div>{/if}</td>
              <td class="num">{#if h.dropped != null}{number.format(h.dropped)}{:else}<span class="nil" aria-label="none"></span>{/if}</td>
              <td class="hide-sm nowrap">{#if h.active && h.lastAppliedAt}<Time iso={h.lastAppliedAt} />{:else}<span class="nil" aria-label="none"></span>{/if}</td>
            </tr>
            {#if h.lastError && h.wanted && !h.active}
              <tr class="errrow"><td colspan="6"><div class="err small">{h.lastError}</div></td></tr>
            {/if}
          {/each}
        </tbody>
      </table>
    {:else}
      <div class="empty">No hosts enrolled yet.</div>
    {/if}
  </section>
{:else if !error}
  <div class="skeleton-block"></div>
{/if}

<style>
  .m0 { margin: 0; }
  .card + .card, .card + .grid-2, .grid-2 + .card { margin-top: var(--space-md); }
  .grid-2 > .card + .card { margin-top: 0; }
  .banner { margin-bottom: var(--space-md); }
  .fleet-row { display: flex; justify-content: space-between; align-items: center; gap: var(--space-sm) var(--space-md); flex-wrap: wrap; }
  .fleet-text { flex: 1 1 320px; }
  .fleet h2 { margin: 0 0 var(--space-2xs); font-size: var(--text-section); display: flex; align-items: center; gap: var(--space-xs); }
  .fleet p { margin: 0; max-width: 75ch; }
  .lists .pick { width: 52px; text-align: center; }
  .lists td.pick { padding-left: var(--space-md); }
  .lists .desc { min-width: 240px; }
  .lists .desc > div { margin-top: var(--space-3xs); }
  .lists .desc strong { font-family: var(--font-display); font-weight: 600; }
  .lists tr.off .desc strong { font-weight: 500; color: var(--color-ink-2); }
  .meta { display: flex; flex-wrap: wrap; gap: 0 var(--space-xs); }
  .meta > span + span { padding-left: var(--space-xs); border-left: var(--rule-hair) solid var(--color-rule-2); }
  .status { min-width: 120px; }
  .status > div { margin-top: var(--space-3xs); }
  .err { color: var(--bad); overflow-wrap: anywhere; max-width: 320px; }
  .errrow td { height: auto; padding-top: 0; padding-bottom: var(--space-xs); }
  .errrow .err { max-width: none; }
  tr:has(+ .errrow) td { border-bottom: 0; }
  .inline { display: flex; gap: var(--space-xs); flex-wrap: wrap; }
  .inline input { flex: 1 1 180px; }
  .chips { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: var(--space-2xs); }
  .chips li { display: inline-flex; align-items: center; gap: var(--space-3xs); min-height: 26px; padding: 0 var(--space-3xs) 0 var(--space-xs); border-radius: 4px; background: var(--color-paper-3); color: var(--color-ink); }
  .chips .x { display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; padding: 0; border: 0; border-radius: 3px; background: none; color: var(--muted); cursor: pointer; transition: color var(--dur-micro) var(--ease-out); }
  .chips .x:hover:not(:disabled) { color: var(--bad); background: var(--color-paper-2); }
  .chips .x:disabled { opacity: 0.55; cursor: not-allowed; }
</style>
