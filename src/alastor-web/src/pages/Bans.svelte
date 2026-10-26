<script lang="ts">
  import { api, errorText, type AllowlistEntry, type Ban, type BanHour } from '../lib/api';
  import { banBuckets, banSeries } from '../lib/stats';
  import StackedBars from '../lib/ui/StackedBars.svelte';
  import { fleet } from '../lib/fleet.svelte';
  import { refreshOn } from '../lib/live.svelte';
  import { route } from '../lib/router.svelte';
  import { canWrite } from '../lib/session.svelte';
  import { toast } from '../lib/toast.svelte';
  import { number } from '../lib/format';
  import { confirm } from '../lib/ui/confirm.svelte';
  import BanDialog from '../lib/BanDialog.svelte';
  import BanTable from '../lib/BanTable.svelte';
  import Time from '../lib/ui/Time.svelte';

  const p = new URLSearchParams(route.search);
  let hostId = $state(p.get('host') ?? '');
  let q = $state(p.get('q') ?? '');
  let kind = $state<'' | 'manual' | 'auto'>('');
  let bans = $state<Ban[]>([]);
  let allowlist = $state<AllowlistEntry[]>([]);
  let loading = $state(true);
  let error = $state('');
  let banOpen = $state(false);
  let hours = $state(24);
  let activity = $state<BanHour[] | null>(null);

  const loadActivity = async () =>
    (activity = await api<BanHour[]>(`/api/stats/bans?hours=${hours}${hostId ? `&hostId=${hostId}` : ''}`).catch(() => activity));
  $effect(() => {
    void hours;
    void hostId;
    loadActivity();
  });
  $effect(() => refreshOn(['eventsCreated'], loadActivity, 60_000));

  async function load() {
    const params = new URLSearchParams();
    if (hostId) params.set('hostId', hostId);
    if (q.trim()) params.set('q', q.trim());
    if (kind) params.set('manual', String(kind === 'manual'));
    try {
      [bans, allowlist] = await Promise.all([api<Ban[]>(`/api/bans?${params}`), api<AllowlistEntry[]>('/api/allowlist')]);
      error = '';
    } catch (e) {
      error = errorText(e);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    const params = new URLSearchParams();
    if (hostId) params.set('host', hostId);
    if (q.trim()) params.set('q', q.trim());
    history.replaceState(null, '', params.size ? `/bans?${params}` : '/bans');
    const t = setTimeout(load, 250);
    return () => clearTimeout(t);
  });

  $effect(() => refreshOn(['bansChanged', 'policyChanged', 'commandUpdated'], load));

  const distinctTargets = $derived(new Set(bans.map((b) => b.target)).size);

  // ---- Allowlist ----
  let allowTarget = $state('');
  let allowNote = $state('');
  let allowBusy = $state(false);
  let allowError = $state('');

  async function addAllow(e: SubmitEvent) {
    e.preventDefault();
    allowBusy = true;
    allowError = '';
    try {
      const entry = await api<AllowlistEntry>('/api/allowlist', { method: 'POST', body: JSON.stringify({ target: allowTarget.trim(), note: allowNote.trim() || null }) });
      allowlist = [...allowlist, entry].sort((a, b) => a.target.localeCompare(b.target));
      toast(`${entry.target} allowlisted. Agents add it to fail2ban's ignoreip or CrowdSec's whitelist and lift any existing bans for it.`);
      allowTarget = '';
      allowNote = '';
    } catch (err) {
      allowError = errorText(err);
    } finally {
      allowBusy = false;
    }
  }

  async function removeAllow(a: AllowlistEntry) {
    if (!(await confirm(`Remove ${a.target} from the allowlist?`, 'fail2ban or CrowdSec will be able to ban it again on every host.', { confirmLabel: 'Remove', danger: true }))) return;
    try {
      await api(`/api/allowlist/${a.id}`, { method: 'DELETE' });
      allowlist = allowlist.filter((x) => x.id !== a.id);
      toast(`${a.target} removed from the allowlist.`);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }
</script>

<div class="page-head">
  <div>
    <h1>Bans</h1>
    <p class="sub">Current bans reported by fail2ban or CrowdSec on each host, plus the fleet-wide allowlist.</p>
  </div>
  {#if canWrite()}<div class="actions"><button class="btn solid-danger" onclick={() => (banOpen = true)}>Ban IP or CIDR</button></div>{/if}
</div>

<nav class="tabs" aria-label="Bans sections"><a href="/bans" class="on" aria-current="page">Bans &amp; allowlist</a><a href="/blocklists">Blocklists</a></nav>

<div class="layout">
  <section class="main">
    <div class="filterbar">
      <input class="field grow" type="search" placeholder="Filter by IP or jail…" bind:value={q} aria-label="Filter bans" />
      <select class="field" bind:value={hostId} aria-label="Host">
        <option value="">All hosts</option>
        {#each fleet.hosts as h (h.id)}<option value={h.id}>{h.name}</option>{/each}
      </select>
      <select class="field" bind:value={kind} aria-label="Ban type">
        <option value="">Automatic and manual</option>
        <option value="auto">Automatic (jails)</option>
        <option value="manual">Manual</option>
      </select>
    </div>

    {#if error}<div class="banner bad" role="alert"><p>{error}</p></div>{/if}

    <section class="card activity">
      <header>
        <h2>Ban activity</h2>
        <div class="seg" role="group" aria-label="Range">
          {#each [[24, '24h'], [168, '7d']] as [h, label] (h)}
            <button class:on={hours === h} aria-pressed={hours === h} onclick={() => (hours = h as number)}>{label}</button>
          {/each}
        </div>
      </header>
      <div class="card-body">
        {#if activity}<StackedBars title="Per hour{hostId ? ` on ${fleet.hosts.find((h) => h.id === hostId)?.name ?? 'this host'}` : ', all hosts'}" series={banSeries} buckets={banBuckets(activity)} height={130} empty="No bans or auth failures in this period." />
        {:else}<div class="skeleton-block" style:height="130px"></div>{/if}
      </div>
    </section>

    <div class="card table-wrap">
      <header>
        <h2>{number.format(bans.length)} active ban{bans.length === 1 ? '' : 's'}</h2>
        {#if bans.length}<span class="hint">{number.format(distinctTargets)} distinct target{distinctTargets === 1 ? '' : 's'}</span>{/if}
      </header>
      {#if loading}
        <div class="skeleton-block"></div>
      {:else if bans.length}
        <BanTable {bans} />
      {:else}
        <div class="empty">{q || hostId || kind ? 'No bans match these filters.' : 'No active bans. When fail2ban or CrowdSec bans an address, it appears here within seconds.'}</div>
      {/if}
    </div>
  </section>

  <aside class="card side">
    <header><h2>Allowlist</h2><span class="hint">never banned</span></header>
    <div class="card-body">
      <p class="muted small intro">Addresses here are added to every jail's <code>ignoreip</code>, can't be banned manually and are taken out of every blocklist. Put your office, VPN and monitoring IPs here.</p>
      {#if allowlist.length}
        <ul class="allow">
          {#each allowlist as a (a.id)}
            <li>
              <div class="who">
                <span class="mono target">{a.target}</span>
                {#if a.note}<div class="muted small">{a.note}</div>{/if}
                <div class="meta muted small"><span>{a.createdBy}</span><span><Time iso={a.createdAt} /></span></div>
              </div>
              {#if canWrite()}<button class="btn small danger" onclick={() => removeAllow(a)} aria-label="Remove {a.target}">Remove</button>{/if}
            </li>
          {/each}
        </ul>
      {:else}
        <p class="empty well small">Empty. Loopback is always ignored.</p>
      {/if}
      {#if canWrite()}
        <form class="form add" onsubmit={addAllow}>
          <input class="field mono" bind:value={allowTarget} placeholder="IP or CIDR" required aria-label="IP or CIDR to allowlist" />
          <input class="field" bind:value={allowNote} placeholder="Note (optional)" maxlength="200" aria-label="Note" />
          {#if allowError}<p class="err small" role="alert">{allowError}</p>{/if}
          <button class="btn" disabled={allowBusy}>Add to allowlist</button>
        </form>
      {/if}
    </div>
  </aside>
</div>

<BanDialog bind:open={banOpen} hostIds={hostId ? [hostId] : []} />

<style>
  .activity { margin-bottom: var(--space-md); }
  .layout { display: grid; grid-template-columns: minmax(0, 1fr) 300px; gap: var(--space-md); align-items: start; }
  .main { min-width: 0; }
  .main h2 { min-width: 0; overflow-wrap: break-word; }
  .intro { margin: 0 0 var(--space-sm); }
  .allow { list-style: none; margin: 0 0 var(--space-md); padding: 0; border-top: var(--rule-hair) solid var(--border); }
  .allow li { display: flex; justify-content: space-between; align-items: flex-start; gap: var(--space-xs); padding: var(--space-xs) 0; border-bottom: var(--rule-hair) solid var(--border); }
  .who { display: flex; flex-direction: column; gap: var(--space-3xs); min-width: 0; }
  .target { color: var(--text-strong); overflow-wrap: anywhere; }
  .meta { display: flex; flex-wrap: wrap; gap: 0 var(--space-xs); }
  .meta > span + span { padding-left: var(--space-xs); border-left: var(--rule-hair) solid var(--color-rule-2); }
  .well { margin: 0 0 var(--space-md); padding: var(--space-md); border-radius: var(--radius-input); background: var(--color-paper-2); }
  .add { gap: var(--space-xs); }
  .add .btn { align-self: flex-start; }
  .err { color: var(--bad); margin: 0; }
  @media (max-width: 900px) { .layout { grid-template-columns: 1fr; } }
</style>
