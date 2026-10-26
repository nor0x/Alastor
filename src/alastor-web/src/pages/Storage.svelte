<script lang="ts">
  import { api, errorText, type CleanupDefinition, type Command, type FleetStorage, type FleetStorageRow } from '../lib/api';
  import { bytes } from '../lib/format';
  import { refreshOn } from '../lib/live.svelte';
  import { canWrite } from '../lib/session.svelte';
  import { riskLook } from '../lib/storage';
  import { toast } from '../lib/toast.svelte';
  import { confirm } from '../lib/ui/confirm.svelte';
  import CopyButton from '../lib/ui/CopyButton.svelte';
  import Icon from '../lib/ui/Icon.svelte';
  import Meter from '../lib/ui/Meter.svelte';
  import Modal from '../lib/ui/Modal.svelte';
  import Time from '../lib/ui/Time.svelte';

  const FleetConfirmation = 'delete';

  let data = $state<FleetStorage | null>(null);
  let error = $state('');
  let selected = $state<Set<string>>(new Set());
  let cleanupId = $state('');
  let busy = $state(false);
  let typed = $state('');
  let destructiveOpen = $state(false);

  async function load() {
    try {
      data = await api<FleetStorage>('/api/storage');
      error = '';
    } catch (e) {
      error = errorText(e);
    }
  }
  $effect(() => {
    load();
    return refreshOn(['hostUpdated'], load, 60_000);
  });

  const hosts = $derived(data?.hosts ?? []);
  const catalog = $derived(new Map((data?.catalog ?? []).map((c) => [c.id, c])));
  const full = $derived(hosts.filter((h) => h.diskPercent >= 90));
  const reclaimable = $derived(hosts.reduce((n, h) => n + (h.reclaimableBytes ?? 0), 0));
  const scanned = $derived(hosts.filter((h) => h.scannedAt));

  const applies = (h: FleetStorageRow, id: string) => h.cleanups.find((c) => c.id === id && !c.blocked && ((c.bytes ?? 0) > 0 || (c.bytes === null && (c.items ?? 0) > 0)));
  const top = (h: FleetStorageRow) => h.cleanups.filter((c) => !c.blocked && (c.bytes ?? 0) > 0 && catalog.get(c.id)?.risk !== 'Destructive')
    .sort((a, b) => (b.bytes ?? 0) - (a.bytes ?? 0)).slice(0, 3);

  const chosen = $derived(hosts.filter((h) => selected.has(h.hostId)));
  // Cleanups that would do something on at least one selected host, with what they'd free there.
  const options = $derived.by(() => {
    const out: { def: CleanupDefinition; hosts: number; bytes: number }[] = [];
    for (const def of data?.catalog ?? []) {
      const on = chosen.map((h) => applies(h, def.id)).filter((c) => !!c);
      if (on.length) out.push({ def, hosts: on.length, bytes: on.reduce((n, c) => n + (c!.bytes ?? 0), 0) });
    }
    return out.sort((a, b) => b.bytes - a.bytes);
  });
  const option = $derived(options.find((o) => o.def.id === cleanupId) ?? null);
  $effect(() => {
    if (cleanupId && !options.some((o) => o.def.id === cleanupId)) cleanupId = '';
  });

  function toggle(id: string) {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    selected = next;
  }
  const allSelected = $derived(hosts.length > 0 && hosts.every((h) => selected.has(h.hostId)));
  function toggleAll() {
    selected = allSelected ? new Set() : new Set(hosts.map((h) => h.hostId));
  }

  async function run() {
    if (!option) return;
    const def = option.def;
    if (def.risk === 'Destructive') {
      typed = '';
      destructiveOpen = true;
      return;
    }
    const offline = chosen.filter((h) => !h.online && applies(h, def.id)).length;
    const ok = await confirm(`${def.title} on ${option.hosts} host${option.hosts === 1 ? '' : 's'}?`,
      `${def.description}\n\nEach agent measures it again and runs:\n${def.display.replace(/\s+#.*$/, '')}` +
      (offline ? `\n\n${offline} offline host${offline === 1 ? ' runs' : 's run'} it when the agent reconnects.` : '') +
      (option.hosts < chosen.length ? `\n\nSkipped on ${chosen.length - option.hosts} selected host${chosen.length - option.hosts === 1 ? '' : 's'} where there's nothing to clean.` : ''),
      { confirmLabel: option.bytes ? `Free about ${bytes(option.bytes)}` : 'Clean up' });
    if (ok) await queue();
  }

  async function queue(confirmText?: string) {
    if (!option) return;
    busy = true;
    try {
      const ids = chosen.filter((h) => applies(h, option.def.id)).map((h) => h.hostId);
      const cmds = await api<Command[]>('/api/storage/cleanup', { method: 'POST', body: JSON.stringify({ cleanup: option.def.id, hostIds: ids, confirm: confirmText }) });
      toast(`${option.def.title}: queued on ${cmds.length} host${cmds.length === 1 ? '' : 's'}. Each host's Storage tab shows what it freed.`);
      destructiveOpen = false;
      selected = new Set();
      await load();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      busy = false;
    }
  }
</script>

<div class="page-head">
  <div>
    <h1>Storage</h1>
    <p class="sub">Disk usage across the fleet, fullest first, and what each host can clean up: package caches, old logs, unused container data.</p>
  </div>
</div>

{#if error}<div class="banner bad" role="alert"><p>{error}</p></div>{/if}

{#if data}
  <section class="card summary-card" aria-label="Storage summary">
    <div class="ledger strip">
      <div><span class="figure-label" title="Root filesystem 90% used or more">Almost full</span><span class="figure-value" class:bad={full.length > 0}>{full.length}</span><span class="figure-foot">of {hosts.length} host{hosts.length === 1 ? '' : 's'}</span></div>
      <div><span class="figure-label" title="What the safe and check-first cleanups would free on every host together; unused Docker volumes aren't counted">Can be freed</span><span class="figure-value">{bytes(reclaimable)}</span></div>
      <div><span class="figure-label">Scanned</span><span class="figure-value">{scanned.length}</span><span class="figure-foot">{hosts.length - scanned.length ? `${hosts.length - scanned.length} not yet` : 'all hosts'}</span></div>
    </div>
  </section>
{/if}

{#if canWrite() && selected.size > 0}
  <div class="card bulk" role="region" aria-label="Clean up selected hosts">
    <span class="small"><strong>{selected.size}</strong> host{selected.size === 1 ? '' : 's'} selected</span>
    {#if options.length === 0}
      <span class="muted small">Nothing to clean up on them.</span>
    {:else}
      <select class="field" bind:value={cleanupId} aria-label="Cleanup to run">
        <option value="">Choose a cleanup…</option>
        {#each options as o (o.def.id)}
          <option value={o.def.id}>{o.def.title}{o.bytes ? ` · ${bytes(o.bytes)}` : ''} · {o.hosts} host{o.hosts === 1 ? '' : 's'}{o.def.risk === 'Destructive' ? ' · deletes data' : ''}</option>
        {/each}
      </select>
      {#if option}
        <span class="pill {riskLook[option.def.risk].tone}" title={riskLook[option.def.risk].title}>{riskLook[option.def.risk].label}</span>
        <button class="btn small {option.def.risk === 'Destructive' ? 'danger' : 'primary'}" disabled={busy} onclick={run}>
          {busy ? 'Queuing…' : `${option.def.risk === 'Destructive' ? 'Delete' : 'Clean up'} on ${option.hosts} host${option.hosts === 1 ? '' : 's'}`}
        </button>
      {/if}
    {/if}
    <button class="btn small ghost" onclick={() => (selected = new Set())}>Clear</button>
    {#if option}
      <div class="cmd by-hand"><code>{option.def.display}</code><CopyButton text={option.def.display.replace(/\s+#.*$/, '')} /></div>
    {/if}
  </div>
{/if}

<div class="card">
  {#if !data}
    <div class="skeleton-block"></div>
  {:else if hosts.length === 0}
    <div class="empty">No hosts enrolled yet.</div>
  {:else}
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            {#if canWrite()}<th class="pick"><input type="checkbox" checked={allSelected} onchange={toggleAll} aria-label="Select all hosts" /></th>{/if}
            <th>Host</th>
            <th title="Root filesystem, from the last heartbeat">Disk used</th>
            <th class="num hide-sm">Free</th>
            <th class="num" title="What the safe and check-first cleanups would free">Can be freed</th>
            <th class="hide-sm">Biggest cleanups</th>
            <th class="hide-sm">Scanned</th>
          </tr>
        </thead>
        <tbody>
          {#each hosts as h (h.hostId)}
            <tr class:picked={selected.has(h.hostId)}>
              {#if canWrite()}<td class="pick"><input type="checkbox" checked={selected.has(h.hostId)} onchange={() => toggle(h.hostId)} aria-label="Select {h.name}" /></td>{/if}
              <td>
                <a href="/hosts/{h.hostId}?tab=storage">{h.name}</a>
                {#if !h.online}<span class="pill muted">offline</span>{/if}
                {#if h.groupName}<span class="pill tag">{h.groupName}</span>{/if}
                {#if h.running}<span class="pill info" title="A cleanup is running">{catalog.get(h.running)?.title ?? h.running}</span>{/if}
              </td>
              <td><Meter value={h.diskPercent} warn={80} bad={90} /></td>
              <td class="num hide-sm nowrap">{h.diskTotalBytes ? bytes(h.diskTotalBytes - h.diskUsedBytes) : ''}</td>
              <td class="num nowrap">{#if h.reclaimableBytes !== null}{bytes(h.reclaimableBytes)}{:else}<span class="nil" aria-label="not scanned"></span>{/if}</td>
              <td class="hide-sm">
                <span class="tops">
                  {#each top(h) as c (c.id)}<span class="pill tag" title={catalog.get(c.id)?.description}>{catalog.get(c.id)?.title ?? c.id} · {bytes(c.bytes ?? 0)}</span>{/each}
                </span>
              </td>
              <td class="small muted hide-sm nowrap">{#if h.scannedAt}<Time iso={h.scannedAt} />{:else}not yet{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
<p class="small muted foot">
  Each agent measures its disk on <code>storage.scanSchedule</code> at low CPU and disk priority. A cleanup is measured again on the host right
  before it runs, so it only removes what is there then. Protected packages and the running kernel are never removed.
</p>

<Modal bind:open={destructiveOpen} title={option ? `${option.def.title} on ${option.hosts} host${option.hosts === 1 ? '' : 's'}` : ''}>
  {#if option}
    <div class="stack-sm">
      <div class="banner bad" role="alert">
        <Icon name="error" />
        <p><strong>This deletes data for good{option.bytes ? ` (${bytes(option.bytes)} in total)` : ''}.</strong> {option.def.description}</p>
      </div>
      <p class="small">On {chosen.filter((h) => applies(h, option!.def.id)).map((h) => h.name).join(', ')}.</p>
      <label class="small" for="confirm-fleet">Type <strong class="mono">{FleetConfirmation}</strong> to confirm</label>
      <input id="confirm-fleet" class="field" autocomplete="off" spellcheck="false" bind:value={typed} />
    </div>
  {/if}
  {#snippet footer()}
    <button class="btn" onclick={() => (destructiveOpen = false)}>Cancel</button>
    <button class="btn solid-danger" disabled={typed.trim().toLowerCase() !== FleetConfirmation || busy} onclick={() => queue(typed.trim())}>Delete</button>
  {/snippet}
</Modal>

<style>
  .summary-card { margin-bottom: var(--space-md); }
  .strip { display: flex; flex-wrap: wrap; }
  .strip > div { flex: 1 1 128px; }
  @media (max-width: 640px) { .strip > div { flex: 1 1 50%; min-width: 0; } }
  .bulk { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-xs) var(--space-sm); padding: var(--space-sm) var(--space-md); margin-bottom: var(--space-md); }
  .bulk select { max-width: 100%; }
  .by-hand { flex-basis: 100%; }
  .pick { width: 32px; }
  tr.picked td { background: var(--color-paper-2); }
  .tops { display: inline-flex; flex-wrap: wrap; gap: var(--space-2xs); }
  .foot { margin-top: var(--space-sm); }
  .stack-sm { display: flex; flex-direction: column; gap: var(--space-xs); }
  .stack-sm p { margin: 0; }
</style>
