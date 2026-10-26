<script lang="ts">
  import { untrack } from 'svelte';
  import { api, errorText, type Command, type DirectoryUsage, type HostStorage, type StorageCleanup } from './api';
  import { bytes, fullDate, number } from './format';
  import { on, refreshOn } from './live.svelte';
  import { canWrite } from './session.svelte';
  import { diskTone, fileInfo, folderInfo, riskLook, usedPercent } from './storage';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
  import CopyButton from './ui/CopyButton.svelte';
  import Icon from './ui/Icon.svelte';
  import Modal from './ui/Modal.svelte';
  import Time from './ui/Time.svelte';

  let { hostId, hostName, isOnline }: { hostId: string; hostName: string; isOnline: boolean } = $props();

  let data = $state<HostStorage | null>(null);
  let error = $state('');
  let scanning = $state(false);
  let queuing = $state<string | null>(null);
  // The cleanup command we just queued: if the agent refuses it, say why.
  let watching = $state<string | null>(null);
  let expanded = $state<Set<string>>(new Set(['/']));
  let showCommand = $state<string | null>(null);
  let destructive = $state<{ open: boolean; cleanup: StorageCleanup | null; typed: string }>({ open: false, cleanup: null, typed: '' });

  async function load() {
    try {
      const prevScan = data?.scannedAt;
      data = await api<HostStorage>(`/api/hosts/${hostId}/storage`);
      error = '';
      if (scanning && data.scannedAt !== prevScan) scanning = false;
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    void hostId;
    untrack(load);
    const offs = [
      on('hostUpdated', (h: { id: string }) => { if (h.id === hostId) load(); }),
      on('commandUpdated', (c: Command) => {
        if (c.id !== watching) return;
        if (c.status === 'Failed' || c.status === 'Expired') {
          toast(c.resultMessage ?? 'The agent refused the cleanup.', 'error');
          watching = null;
        }
        load();
      }),
      refreshOn(['policyChanged'], load, 60_000),
    ];
    return () => offs.forEach((o) => o());
  });

  const root = $derived(data?.filesystems.find((f) => f.mount === '/') ?? data?.filesystems[0] ?? null);
  const rootPct = $derived(root ? usedPercent(root) : 0);
  const schedule = $derived(data?.schedules.find((s) => s.key === 'storage.scanSchedule'));
  const runningTitle = $derived(data?.running ? (data.cleanups.find((c) => c.id === data!.running!.id)?.title ?? data.running.id) : null);

  // Worth doing first: the biggest, then the ones only counted (autoremove on dnf), then blocked; nothing-to-clean last.
  const hasWork = (c: StorageCleanup) => (c.bytes ?? 0) > 0 || (c.bytes === null && (c.items ?? 0) > 0);
  const actionable = $derived((data?.cleanups ?? []).filter((c) => hasWork(c) && !c.blocked)
    .sort((a, b) => (a.risk === 'Destructive' ? 1 : 0) - (b.risk === 'Destructive' ? 1 : 0) || (b.bytes ?? -1) - (a.bytes ?? -1)));
  const blocked = $derived((data?.cleanups ?? []).filter((c) => hasWork(c) && c.blocked));
  const idle = $derived((data?.cleanups ?? []).filter((c) => !hasWork(c)));
  const destructiveBytes = $derived((data?.cleanups ?? []).filter((c) => c.risk === 'Destructive').reduce((n, c) => n + (c.bytes ?? 0), 0));

  // The folder tree: each scanned mount is a root; a folder's children are the listed folders one level below it.
  const children = $derived.by(() => {
    const map = new Map<string, DirectoryUsage[]>();
    const paths = new Set((data?.directories ?? []).map((d) => d.path));
    for (const d of data?.directories ?? []) {
      if (d.path === '/') continue;
      const parent = d.path.slice(0, d.path.lastIndexOf('/')) || '/';
      if (!paths.has(parent)) continue;
      map.set(parent, [...(map.get(parent) ?? []), d]);
    }
    for (const list of map.values()) list.sort((a, b) => b.bytes - a.bytes);
    return map;
  });
  const roots = $derived.by(() => {
    const paths = new Set((data?.directories ?? []).map((d) => d.path));
    return (data?.directories ?? []).filter((d) => d.path === '/' || !paths.has(d.path.slice(0, d.path.lastIndexOf('/')) || '/'));
  });
  const rows = $derived.by(() => {
    const out: { dir: DirectoryUsage; depth: number; root: DirectoryUsage }[] = [];
    const walk = (d: DirectoryUsage, depth: number, root: DirectoryUsage) => {
      out.push({ dir: d, depth, root });
      if (expanded.has(d.path)) for (const c of children.get(d.path) ?? []) walk(c, depth + 1, root);
    };
    for (const r of roots) walk(r, 0, r);
    return out;
  });

  function toggle(path: string) {
    const next = new Set(expanded);
    if (next.has(path)) next.delete(path);
    else next.add(path);
    expanded = next;
  }

  const name = (path: string, depth: number) => (depth === 0 ? path : path.slice(path.lastIndexOf('/') + 1));
  const size = (c: StorageCleanup) => (c.bytes !== null ? bytes(c.bytes) : c.items !== null ? `${number.format(c.items)} item${c.items === 1 ? '' : 's'}` : '');
  const copyable = (cmd: string) => cmd.replace(/\s+#.*$/, '');
  const byId = (id: string) => data?.cleanups.find((c) => c.id === id);

  async function scan() {
    try {
      await api<Command>(`/api/hosts/${hostId}/actions/scan-storage`, { method: 'POST' });
      scanning = true;
      toast(isOnline ? 'Storage scan requested. On a big disk it can take a few minutes.' : 'The host is offline; it scans when the agent reconnects.');
      setTimeout(() => (scanning = false), 20 * 60_000);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  async function clean(c: StorageCleanup) {
    if (c.risk === 'Destructive') {
      destructive = { open: true, cleanup: c, typed: '' };
      return;
    }
    const ok = await confirm(`${c.title} on ${hostName}?`,
      `${c.description}\n\nThe agent measures it again and runs:\n${copyable(c.command)}` +
      (isOnline ? '' : `\n\n${hostName} is offline; it runs this when the agent reconnects.`),
      { confirmLabel: c.bytes ? `Free ${bytes(c.bytes)}` : 'Clean up' });
    if (ok) await queue(c);
  }

  async function queue(c: StorageCleanup, confirmText?: string) {
    queuing = c.id;
    try {
      const cmd = await api<Command>(`/api/hosts/${hostId}/storage/cleanup`, { method: 'POST', body: JSON.stringify({ cleanup: c.id, confirm: confirmText }) });
      watching = cmd.id;
      toast(`${c.title}: cleanup queued. This page shows the result when the agent reports back.`);
      destructive = { open: false, cleanup: null, typed: '' };
      await load();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      queuing = null;
    }
  }
</script>

{#if error && !data}
  <div class="banner bad" role="alert"><p>Couldn't load disk usage: {error}</p></div>
{:else if !data}
  <div class="skeleton-block"></div>
{:else}
  <div class="stack">
    <section class="card summary">
      <div class="lead">
        <span class="figure-label" title="What the safe and check-first cleanups below would free together. Deleting Docker volumes isn't counted.">Can be freed</span>
        <span class="figure-value">{#if data.scannedAt || data.cleanups.length}{bytes(data.reclaimableBytes)}{:else}<span class="nil" aria-label="unknown"></span>{/if}</span>
      </div>
      <div class="counts">
        {#if root}
          <span class="pair"><strong class="n" class:warn={diskTone(rootPct) === 'warn'} class:bad={diskTone(rootPct) === 'bad'}>{rootPct.toFixed(0)}%</strong> of <code>{root.mount}</code> used</span>
          <span class="pair"><strong class="n">{bytes(root.availableBytes)}</strong> free of {bytes(root.totalBytes)}</span>
        {/if}
        {#if actionable.length}<span class="pair"><strong class="n">{actionable.length}</strong> cleanup{actionable.length === 1 ? '' : 's'} available</span>{/if}
      </div>
      <div class="meta">
        <span class="meta-facts">
          {#if data.scannedAt}<span>Scanned <Time iso={data.scannedAt} /></span>{:else}<span>Not scanned yet</span>{/if}
          {#if schedule}<span title="storage.scanSchedule in the policy">Scans {schedule.value}</span>{/if}
        </span>
        <span class="keys">
          {#if canWrite()}<button class="btn small" onclick={scan} disabled={scanning}>{scanning ? 'Scanning…' : 'Scan now'}</button>{/if}
        </span>
      </div>
    </section>

    {#if root && rootPct >= 90}
      <div class="banner bad" role="alert">
        <Icon name="error" />
        <p>
          <strong>{root.mount} is {rootPct.toFixed(0)}% full.</strong>
          When it fills up, logs stop, databases refuse writes and updates fail.
          {#if actionable.length}Start with the cleanups below{data.reclaimableBytes ? `: together they free about ${bytes(data.reclaimableBytes)}` : ''}.{:else}Look at the biggest folders and files below.{/if}
        </p>
      </div>
    {/if}

    {#if data.success === false && data.error}
      <div class="banner bad" role="alert">
        <Icon name="error" />
        <p><strong>The last scan failed:</strong> <span class="mono small">{data.error}</span>{data.scannedAt ? ' What you see is from the last successful one.' : ''}</p>
      </div>
    {/if}

    {#if !data.scannedAt && !data.cleanups.length}
      <div class="empty empty-dashed">
        This host hasn't reported its disk usage yet. Agents scan on startup and then on <code>storage.scanSchedule</code> ({schedule?.value ?? 'every 12h'}).
        If the agent is older than this server, update it first.
      </div>
    {:else}
      {#if data.running}
        <div class="banner info" aria-live="polite">
          <span class="spinner" aria-hidden="true"></span>
          <p><strong>{runningTitle}</strong>: cleanup running since <Time iso={data.running.startedAt} />. This page updates when the agent reports back.</p>
        </div>
      {/if}

      {#if data.lastCleanup && !data.running}
        {@const l = data.lastCleanup}
        <section class="card">
          <header>
            <h2>Last cleanup</h2>
            <span class="hint"><Time iso={l.atUtc} /></span>
          </header>
          <div class="pad stack-sm">
            {#if l.success}
              <p><span class="pill ok">done</span> {byId(l.id)?.title ?? l.id}: freed <strong>{bytes(l.freedBytes)}</strong>.</p>
            {:else}
              <p><span class="pill bad">failed</span> {byId(l.id)?.title ?? l.id}: <span class="mono small">{l.error}</span></p>
            {/if}
            {#if l.logTail}
              <details class="output">
                <summary>Output</summary>
                <pre class="code-block log">{l.logTail}</pre>
              </details>
            {/if}
          </div>
        </section>
      {/if}

      <section class="card" aria-labelledby="cleanups-h">
        <header>
          <h2 id="cleanups-h">What can be cleaned up</h2>
          {#if data.reportedAt}<span class="hint">Measured <Time iso={data.reportedAt} /></span>{/if}
        </header>
        {#if actionable.length === 0 && blocked.length === 0}
          <div class="empty">Nothing to clean up: caches, old logs and unused container data are already small. See the biggest folders and files below.</div>
        {:else}
          <ul class="cleanups">
            {#each [...actionable, ...blocked] as c (c.id)}
              {@const look = riskLook[c.risk]}
              <li id="cleanup-{c.id}">
                <div class="c-main">
                  <div class="c-title">
                    <strong>{c.title}</strong>
                    <span class="pill {look.tone}" title={look.title}>{look.label}</span>
                  </div>
                  <p class="small">{c.description}</p>
                  {#if c.detail}<p class="small muted mono detail-line">{c.detail}</p>{/if}
                  {#if c.blocked}<p class="small blocked"><Icon name="alert" /> Not offered here: {c.blocked}</p>{/if}
                  {#if showCommand === c.id}
                    <div class="cmd"><code>{c.command}</code><CopyButton text={copyable(c.command)} /></div>
                  {/if}
                </div>
                <div class="c-size">
                  <span class="figure-value small-figure">{size(c)}</span>
                </div>
                <div class="c-actions">
                  {#if data.running?.id === c.id}
                    <span class="muted small waiting"><span class="spinner" aria-hidden="true"></span> Cleaning…</span>
                  {:else if canWrite() && !c.blocked}
                    <button class="btn small {c.risk === 'Destructive' ? 'danger' : 'primary'}" disabled={!!data.running || queuing === c.id}
                      title={data.running ? 'Another cleanup is still running on this host' : undefined} onclick={() => clean(c)}>
                      {queuing === c.id ? 'Queuing…' : c.risk === 'Destructive' ? 'Delete…' : 'Clean up'}
                    </button>
                  {/if}
                  <button class="btn small ghost" aria-expanded={showCommand === c.id} onclick={() => (showCommand = showCommand === c.id ? null : c.id)}>
                    {showCommand === c.id ? 'Hide command' : 'Command'}
                  </button>
                </div>
              </li>
            {/each}
          </ul>
        {/if}
        {#if idle.length}
          <p class="small muted idle">Nothing to clean right now: {idle.map((c) => c.title).join(', ')}.</p>
        {/if}
        {#if destructiveBytes > 0}
          <p class="small muted idle">"Can be freed" leaves out the {bytes(destructiveBytes)} in unused Docker volumes: deleting them loses their data.</p>
        {/if}
      </section>

      <section class="card" aria-labelledby="fs-h">
        <header><h2 id="fs-h">Filesystems</h2></header>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>Mounted on</th>
                <th class="hide-sm">Device</th>
                <th>Used</th>
                <th class="num">Free</th>
                <th class="num hide-sm" title="Every file needs an inode. A filesystem with no inodes left is full, however much space it shows.">Inodes</th>
              </tr>
            </thead>
            <tbody>
              {#each data.filesystems as f (f.mount)}
                {@const pct = usedPercent(f)}
                <tr>
                  <td class="mono">{f.mount}</td>
                  <td class="mono small muted hide-sm">{f.device} <span class="pill tag">{f.type}</span></td>
                  <td>
                    <span class="usage">
                      <span class="gauge {diskTone(pct) === 'ok' ? '' : diskTone(pct)}" style:--v={pct}></span>
                      <span class="small"><strong>{pct.toFixed(0)}%</strong> <span class="muted">· {bytes(f.usedBytes)} of {bytes(f.totalBytes)}</span></span>
                    </span>
                  </td>
                  <td class="num">{bytes(f.availableBytes)}</td>
                  <td class="num hide-sm" class:bad-text={(f.inodesUsedPercent ?? 0) >= 90}>{f.inodesUsedPercent === null ? '' : `${f.inodesUsedPercent}%`}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>

      <section class="card" aria-labelledby="dirs-h">
        <header>
          <h2 id="dirs-h">Biggest folders</h2>
          <span class="hint">Folders under 25 MB aren't listed</span>
        </header>
        {#if rows.length === 0}
          <div class="empty">No folder sizes in this scan.</div>
        {:else}
          <ul class="tree" role="tree" aria-label="Folders by size">
            {#each rows as { dir, depth, root: top } (dir.path)}
              {@const info = folderInfo(dir.path)}
              {@const kids = children.get(dir.path) ?? []}
              {@const share = top.bytes > 0 ? (dir.bytes * 100) / top.bytes : 0}
              {@const fixes = (info?.cleanups ?? []).map(byId).filter((c) => c && hasWork(c) && !c.blocked) as StorageCleanup[]}
              <li role="treeitem" aria-level={depth + 1} aria-expanded={kids.length ? expanded.has(dir.path) : undefined} aria-selected="false" style:--depth={depth}>
                <div class="t-row">
                  <span class="t-name">
                    {#if kids.length}
                      <button class="twisty" class:open={expanded.has(dir.path)} onclick={() => toggle(dir.path)} aria-label="{expanded.has(dir.path) ? 'Collapse' : 'Expand'} {dir.path}"></button>
                    {:else}<span class="twisty-space" aria-hidden="true"></span>{/if}
                    <span class="mono" title={dir.path}>{name(dir.path, depth)}</span>
                  </span>
                  <span class="track" title="{share.toFixed(1)}% of {top.path}"><span class="fill" style:width="{share}%"></span></span>
                  <span class="t-size">{bytes(dir.bytes)}</span>
                </div>
                {#if info || fixes.length}
                  <div class="t-info small muted">
                    {#if info}{info.what}{/if}
                    {#each fixes as c (c.id)}<a class="fix" href="#cleanup-{c.id}">{c.title}{c.bytes ? `: ${bytes(c.bytes)}` : ''}</a>{/each}
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      </section>

      <section class="card" aria-labelledby="files-h">
        <header>
          <h2 id="files-h">Biggest files</h2>
          <span class="hint">100 MB and up</span>
        </header>
        {#if data.largestFiles.length === 0}
          <div class="empty">No file of 100 MB or more.</div>
        {:else}
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>File</th><th class="num">Size</th><th class="hide-sm">Modified</th></tr></thead>
              <tbody>
                {#each data.largestFiles as f (f.path)}
                  {@const what = fileInfo(f.path)}
                  <tr>
                    <td>
                      <span class="mono small path">{f.path}</span>
                      {#if what}<div class="small muted">{what}</div>{/if}
                    </td>
                    <td class="num nowrap">{bytes(f.bytes)}</td>
                    <td class="small muted hide-sm nowrap">{f.modifiedUtc ? fullDate(f.modifiedUtc) : ''}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      </section>

      {#if data.notes.length}
        <details class="output notes">
          <summary>{data.notes.length} note{data.notes.length === 1 ? '' : 's'} from the scan</summary>
          <ul class="small muted">{#each data.notes as n, i (i)}<li class="mono">{n}</li>{/each}</ul>
        </details>
      {/if}
    {/if}
  </div>

  <Modal bind:open={destructive.open} title={destructive.cleanup ? `${destructive.cleanup.title} on ${hostName}` : ''}>
    {#if destructive.cleanup}
      {@const c = destructive.cleanup}
      <div class="stack-sm">
        <div class="banner bad" role="alert">
          <Icon name="error" />
          <p><strong>This deletes data for good{c.bytes ? ` (${bytes(c.bytes)})` : ''}.</strong> {c.description}</p>
        </div>
        {#if c.detail}<p class="small mono">{c.detail}</p>{/if}
        <p class="small">The agent runs:</p>
        <div class="cmd"><code>{copyable(c.command)}</code></div>
        <label class="small" for="confirm-host">Type <strong class="mono">{hostName}</strong> to confirm</label>
        <input id="confirm-host" class="field" autocomplete="off" spellcheck="false" bind:value={destructive.typed} />
      </div>
    {/if}
    {#snippet footer()}
      <button class="btn" onclick={() => (destructive.open = false)}>Cancel</button>
      <button class="btn solid-danger" disabled={!destructive.cleanup || destructive.typed.trim().toLowerCase() !== hostName.toLowerCase() || queuing !== null}
        onclick={() => destructive.cleanup && queue(destructive.cleanup, destructive.typed.trim())}>Delete</button>
    {/snippet}
  </Modal>
{/if}

<style>
  /* The summary ledger, the same strip on every host tab: lead figure | counts | when + keys, parted by hairlines. */
  .summary { display: grid; grid-template-columns: minmax(200px, max-content) minmax(0, 1fr) minmax(0, max-content); overflow: hidden; }
  .summary > * { display: flex; flex-direction: column; justify-content: center; gap: var(--space-2xs); min-width: 0; padding: var(--space-md); }
  .summary > * + * { box-shadow: inset 1px 0 0 var(--border); }
  .lead .figure-value { display: inline-flex; align-items: baseline; }
  .lead .figure-value .nil { width: 24px; height: 2px; align-self: center; }
  .counts { flex-direction: row; flex-wrap: wrap; align-items: center; align-content: center; justify-content: flex-start; gap: var(--space-xs) var(--space-lg); color: var(--muted); }
  .pair { display: inline-flex; align-items: baseline; gap: var(--space-2xs); color: var(--muted); }
  .pair .n { font-family: var(--font-display); font-weight: 600; font-size: var(--text-lg); line-height: 1; color: var(--text-strong); font-variant-numeric: tabular-nums; }
  .pair .n.warn { color: var(--warn); }
  .pair .n.bad { color: var(--bad); }
  .pair code { font-size: var(--text-code); }
  .meta { align-items: flex-end; text-align: right; }
  .meta-facts { display: flex; flex-direction: column; align-items: inherit; gap: var(--space-3xs); font-size: var(--text-sm); color: var(--muted); }
  .keys { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: var(--space-xs); margin-top: var(--space-2xs); }
  .keys:empty { display: none; }
  @media (max-width: 760px) {
    .summary { grid-template-columns: minmax(0, 1fr); }
    .summary > * + * { box-shadow: inset 0 1px 0 var(--border); }
    .counts:empty { display: none; }
    .meta { align-items: flex-start; text-align: left; }
    .keys { justify-content: flex-start; }
  }

  .pad { padding: var(--space-md); }
  .stack-sm { display: flex; flex-direction: column; gap: var(--space-xs); }
  .stack-sm p { margin: 0; }
  .banner .spinner { margin-top: 4px; }
  .spinner { display: inline-block; flex: none; width: 12px; height: 12px; border: 2px solid var(--color-rule-2); border-top-color: var(--color-accent); border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .spinner { animation: none; } }
  .waiting { display: inline-flex; align-items: center; gap: var(--space-xs); }

  .cleanups { list-style: none; margin: 0; padding: 0; }
  .cleanups li { display: grid; grid-template-columns: minmax(0, 1fr) max-content max-content; gap: var(--space-xs) var(--space-md); align-items: start; padding: var(--space-sm) var(--space-md); scroll-margin-top: var(--space-xl); }
  .cleanups li + li { border-top: var(--rule-hair) solid var(--border); }
  .cleanups li:target { background: var(--color-paper-2); }
  .c-main { display: flex; flex-direction: column; gap: var(--space-2xs); min-width: 0; }
  .c-main p { margin: 0; }
  .c-title { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-xs); }
  .detail-line { overflow-wrap: anywhere; }
  .blocked { display: inline-flex; align-items: flex-start; gap: var(--space-2xs); color: var(--warn); }
  .c-size { text-align: right; }
  .small-figure { font-size: var(--text-lg); white-space: nowrap; }
  .c-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: var(--space-2xs); }
  .cmd { margin-top: var(--space-2xs); }
  @media (max-width: 640px) {
    .cleanups li { grid-template-columns: minmax(0, 1fr) max-content; }
    .c-actions { grid-column: 1 / -1; justify-content: flex-start; }
  }
  .idle { margin: 0; padding: var(--space-sm) var(--space-md); border-top: var(--rule-hair) solid var(--border); }

  .usage { display: inline-flex; align-items: center; gap: var(--space-xs); flex-wrap: wrap; }
  .usage .gauge { width: 96px; }
  .bad-text { color: var(--bad); font-weight: 600; }

  .tree { list-style: none; margin: 0; padding: var(--space-xs) var(--space-md) var(--space-sm); }
  .tree li { padding: var(--space-2xs) 0 var(--space-2xs) calc(var(--depth) * 20px); }
  .tree li + li { border-top: var(--rule-hair) solid var(--border); }
  .t-row { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(48px, 2fr) 72px; align-items: center; gap: var(--space-sm); min-height: 28px; }
  .t-name { display: inline-flex; align-items: center; gap: var(--space-2xs); min-width: 0; }
  .t-name .mono { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: var(--text-code); }
  .twisty, .twisty-space { flex: none; width: 20px; height: 20px; }
  .twisty { display: inline-grid; place-items: center; padding: 0; border: 0; border-radius: 4px; background: none; cursor: pointer; color: var(--muted); }
  .twisty::before { content: ''; width: 6px; height: 6px; border-right: 1.5px solid currentColor; border-bottom: 1.5px solid currentColor; transform: rotate(-45deg); transition: transform 0.12s; }
  .twisty.open::before { transform: rotate(45deg); }
  .twisty:hover { background: var(--color-paper-3); color: var(--text-strong); }
  .track { height: 10px; background: var(--color-paper-3); border-radius: 2px; }
  .fill { display: block; height: 100%; min-width: 2px; border-radius: 2px; background: var(--color-accent); }
  .t-size { text-align: right; font-family: var(--font-display); font-weight: 600; font-variant-numeric: tabular-nums; color: var(--text-strong); white-space: nowrap; }
  .t-info { display: flex; flex-wrap: wrap; align-items: baseline; gap: var(--space-2xs) var(--space-sm); padding: 0 0 var(--space-2xs) 22px; }
  .fix { white-space: nowrap; }
  .fix::before { content: '→ '; }
  @media (max-width: 640px) { .t-row { grid-template-columns: minmax(0, 1fr) 64px; } .track { display: none; } }

  .path { overflow-wrap: anywhere; }
  .output > summary { width: fit-content; cursor: pointer; font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--color-ink-2); }
  .output > summary:hover { color: var(--text-strong); }
  .output[open] > summary { margin-bottom: var(--space-xs); }
  .notes ul { margin: 0; padding-left: var(--space-md); }
  .log { max-height: 320px; }
</style>
