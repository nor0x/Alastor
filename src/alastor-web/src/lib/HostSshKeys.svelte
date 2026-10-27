<script lang="ts">
  import { untrack } from 'svelte';
  import { api, errorText, type AuthorizedKey, type Command, type HostSshKeys, type KeyAccount } from './api';
  import { on, refreshOn } from './live.svelte';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
  import CopyButton from './ui/CopyButton.svelte';
  import Icon from './ui/Icon.svelte';
  import Modal from './ui/Modal.svelte';
  import Time from './ui/Time.svelte';

  // Which keys let whom in over SSH on this host, from the agent's key scan. Admins add and remove keys here; the agent
  // re-checks each change, writes the file and scans again, so this list is always what's on disk.
  let { hostId, hostName, isOnline }: { hostId: string; hostName: string; isOnline: boolean } = $props();

  let data = $state<HostSshKeys | null>(null);
  let error = $state('');
  let scanning = $state(false);
  let busy = $state(false);
  // Key-change commands we queued: when the agent refuses one, say why.
  let watching = $state<Set<string>>(new Set());
  let adding = $state<{ open: boolean; user: string; key: string; error: string }>({ open: false, user: '', key: '', error: '' });

  async function load() {
    try {
      const prev = data?.scannedAt;
      data = await api<HostSshKeys>(`/api/hosts/${hostId}/ssh-keys`);
      error = '';
      if (scanning && data.scannedAt !== prev) scanning = false;
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
        if (!watching.has(c.id)) return;
        if (c.status === 'Failed' || c.status === 'Expired') toast(c.resultMessage ?? 'The agent refused the change.', 'error');
        else if (c.status === 'Succeeded' && c.resultMessage) toast(c.resultMessage);
        if (c.status !== 'Pending' && c.status !== 'Delivered') {
          const next = new Set(watching);
          next.delete(c.id);
          watching = next;
        }
        load();
      }),
      refreshOn(['policyChanged'], load, 60_000),
    ];
    return () => offs.forEach((o) => o());
  });

  const schedule = $derived(data?.schedules.find((s) => s.key === 'logins.keysSchedule'));
  const withKeys = $derived((data?.accounts ?? []).filter((a) => a.keys.length > 0));
  const withoutKeys = $derived((data?.accounts ?? []).filter((a) => a.keys.length === 0));
  const total = $derived(withKeys.reduce((n, a) => n + a.keys.length, 0));
  const weak = $derived(withKeys.flatMap((a) => a.keys.filter((k) => k.weakness)).length);
  const adminKeys = $derived(withKeys.filter((a) => a.admin).reduce((n, a) => n + a.keys.length, 0));
  // Mirrors the agent's lockout guard, so the button says why before anyone clicks it.
  const guarded = $derived(!!data && !data.keysCommand && data.passwordLogin !== true && adminKeys <= 1);

  const pendingRemoval = (user: string, fp: string) => data?.pending.some((p) => p.op === 'remove' && p.user === user && p.fingerprint === fp) ?? false;
  const keySize = (k: AuthorizedKey) => (k.bits && (k.type === 'ssh-rsa' || k.type === 'ssh-dss') ? `${k.typeName} ${k.bits}` : k.typeName);
  const shortFile = (a: KeyAccount, file: string) => (file.startsWith(a.home.replace(/\/$/, '') + '/') ? '~' + file.slice(a.home.replace(/\/$/, '').length) : file);

  function watch(id: string) {
    watching = new Set([...watching, id]);
  }

  async function scan() {
    try {
      await api<Command>(`/api/hosts/${hostId}/actions/scan-ssh-keys`, { method: 'POST' });
      scanning = true;
      toast(isOnline ? 'Key scan requested.' : 'The host is offline; it scans when the agent reconnects.');
      setTimeout(() => (scanning = false), 2 * 60_000);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  function openAdd(user?: string) {
    const fallback = data?.accounts.find((a) => a.admin && a.uid !== 0) ?? data?.accounts[0];
    adding = { open: true, user: user ?? fallback?.user ?? '', key: '', error: '' };
  }

  async function add() {
    busy = true;
    adding.error = '';
    try {
      const cmd = await api<Command>(`/api/hosts/${hostId}/ssh-keys`, { method: 'POST', body: JSON.stringify({ user: adding.user, key: adding.key }) });
      watch(cmd.id);
      toast(isOnline ? `Adding the key for ${adding.user}…` : `${hostName} is offline; the key is added when the agent reconnects.`);
      adding = { open: false, user: '', key: '', error: '' };
      await load();
    } catch (e) {
      adding.error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function remove(a: KeyAccount, k: AuthorizedKey) {
    const ok = await confirm(`Remove this key from ${a.user} on ${hostName}?`,
      `${keySize(k)} ${k.fingerprint}${k.comment ? ` (${k.comment})` : ''}\n\n` +
      `Whoever holds the matching private key can no longer log in as ${a.user}. Sessions already open stay open.` +
      (isOnline ? '' : `\n\n${hostName} is offline; the key is removed when the agent reconnects.`),
      { confirmLabel: 'Remove key', danger: true });
    if (!ok) return;
    busy = true;
    try {
      const cmd = await api<Command>(`/api/hosts/${hostId}/ssh-keys/remove`, { method: 'POST', body: JSON.stringify({ user: a.user, fingerprint: k.fingerprint }) });
      watch(cmd.id);
      await load();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      busy = false;
    }
  }
</script>

{#if error && !data}
  <div class="banner bad" role="alert"><p>Couldn't load SSH keys: {error}</p></div>
{:else if !data}
  <div class="skeleton-block"></div>
{:else}
  <div class="stack">
    <section class="card summary">
      <div class="lead">
        <span class="figure-label" title="Keys in the authorized_keys files sshd reads, across all accounts">Authorized keys</span>
        <span class="figure-value">{#if data.scannedAt}{total}{:else}<span class="nil" aria-label="unknown"></span>{/if}</span>
      </div>
      <div class="counts">
        {#if data.scannedAt}
          <span class="pair"><strong class="n">{withKeys.length}</strong> account{withKeys.length === 1 ? '' : 's'} with keys</span>
          <span class="pair"><strong class="n">{adminKeys}</strong> admin key{adminKeys === 1 ? '' : 's'}</span>
          {#if weak}<span class="pair"><strong class="n warn">{weak}</strong> weak</span>{/if}
          <span class="pair" title="PasswordAuthentication / KbdInteractiveAuthentication in sshd -T">
            {#if data.passwordLogin === false}passwords off: keys only{:else if data.passwordLogin}passwords accepted too{:else}password login unknown{/if}
          </span>
        {/if}
      </div>
      <div class="meta">
        <span class="meta-facts">
          {#if data.scannedAt}<span>Scanned <Time iso={data.scannedAt} /></span>{:else}<span>Not scanned yet</span>{/if}
          {#if schedule}<span title="logins.keysSchedule in the policy">Scans {schedule.value}</span>{/if}
        </span>
        <span class="keys">
          {#if canWrite()}
            <button class="btn small" onclick={scan} disabled={scanning}>{scanning ? 'Scanning…' : 'Scan now'}</button>
            {#if data.accounts.length}<button class="btn small primary" onclick={() => openAdd()}>Add key</button>{/if}
          {/if}
        </span>
      </div>
    </section>

    {#if data.success === false && data.error}
      <div class="banner bad" role="alert">
        <Icon name="error" />
        <p><strong>The last key scan failed:</strong> <span class="mono small">{data.error}</span>{data.scannedAt ? ' What you see is from the last successful one.' : ''}</p>
      </div>
    {/if}

    {#if data.keysCommand}
      <div class="banner info">
        <Icon name="info" />
        <p>sshd also gets keys from an <code>AuthorizedKeysCommand</code> (LDAP, a cloud metadata service). Those keys aren't listed here and can't be changed from Alastor.</p>
      </div>
    {/if}

    {#if weak}
      <div class="banner warn">
        <Icon name="alert" />
        <p><strong>{weak} weak key{weak === 1 ? '' : 's'}.</strong> DSA keys and RSA keys under 2048 bits can be broken or are refused by current OpenSSH. Add an Ed25519 key (<code>ssh-keygen -t ed25519</code>) and remove the old one.</p>
      </div>
    {/if}

    {#if data.pending.length}
      <div class="banner info" role="status">
        <span class="spinner" aria-hidden="true"></span>
        <p>
          {#each data.pending as p, i (p.commandId)}{i ? '; ' : ''}{p.op === 'add' ? 'Adding' : 'Removing'} <span class="mono">{p.fingerprint ?? 'a key'}</span> {p.op === 'add' ? 'for' : 'from'} <strong>{p.user}</strong>{/each}.
          {isOnline ? 'Waiting for the agent.' : `${hostName} is offline; this runs when the agent reconnects.`}
        </p>
      </div>
    {/if}

    {#if !data.scannedAt}
      <div class="empty empty-dashed">
        This host hasn't reported its SSH keys yet. Agents scan on startup and then on <code>logins.keysSchedule</code> ({schedule?.value ?? 'every 1h'}).
        If the agent is older than this server, update it first.
      </div>
    {:else}
      {#each withKeys as a (a.user)}
        <section class="card">
          <header>
            <h2 class="account">
              <span class="mono" class:root={a.uid === 0}>{a.user}</span>
              {#if a.admin}<span class="pill warn" title="root, or a member of sudo / wheel / admin">admin</span>{/if}
            </h2>
            <span class="hint">
              <span class="mono files">{a.files.map((f) => shortFile(a, f)).join(' · ')}</span>
              {#if canWrite()}<button class="btn small" onclick={() => openAdd(a.user)}>Add key</button>{/if}
            </span>
          </header>
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Key</th><th>Fingerprint</th><th class="hide-sm">Comment</th><th class="hide-sm" title="The authorized_keys file and line it's in">File</th>{#if canWrite()}<th></th>{/if}</tr></thead>
              <tbody>
                {#each a.keys as k (k.file + k.fingerprint + k.line)}
                  <tr>
                    <td class="nowrap">
                      {keySize(k)}
                      {#if k.weakness}<span class="pill warn" title={k.weakness}>weak</span>{/if}
                      {#if k.options}<span class="pill info" title={k.options}>restricted</span>{/if}
                    </td>
                    <td><span class="fp"><span class="mono small">{k.fingerprint}</span><CopyButton text={k.fingerprint} /></span></td>
                    <td class="hide-sm comment">{#if k.comment}{k.comment}{:else}<span class="muted">none</span>{/if}</td>
                    <td class="hide-sm nowrap small muted mono">{shortFile(a, k.file)}:{k.line}</td>
                    {#if canWrite()}
                      <td class="num">
                        {#if pendingRemoval(a.user, k.fingerprint)}<span class="small muted">removing…</span>
                        {:else}
                          <button class="btn small danger" disabled={busy || (guarded && a.admin)}
                            title={guarded && a.admin ? 'The last admin key, and sshd takes no passwords: removing it would lock everyone out. Add another admin key first.' : undefined}
                            onclick={() => remove(a, k)}>Remove</button>
                        {/if}
                      </td>
                    {/if}
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>
      {:else}
        <div class="empty empty-dashed">No account on {hostName} has an authorized SSH key.{#if canWrite() && data.accounts.length} Add one so admins can log in without a password.{/if}</div>
      {/each}

      {#if withoutKeys.length}
        <p class="small muted others">
          Without keys: {#each withoutKeys as a, i (a.user)}{i ? ', ' : ''}<span class="mono">{a.user}</span>{/each}.
        </p>
      {/if}

      {#if data.notes.length}
        <details class="output notes">
          <summary>{data.notes.length} note{data.notes.length === 1 ? '' : 's'} from the scan</summary>
          <ul class="small muted">{#each data.notes as n, i (i)}<li class="mono">{n}</li>{/each}</ul>
        </details>
      {/if}
    {/if}
  </div>

  <Modal bind:open={adding.open} title={`Add an SSH key on ${hostName}`}>
    <div class="stack-sm">
      <label class="small" for="key-user">Account</label>
      <select id="key-user" class="field" bind:value={adding.user}>
        {#each data.accounts as a (a.user)}<option value={a.user}>{a.user}{a.admin ? ' (admin)' : ''}</option>{/each}
      </select>
      <label class="small" for="key-text">Public key</label>
      <textarea id="key-text" class="field mono small" rows="4" spellcheck="false" autocomplete="off" placeholder="ssh-ed25519 AAAAC3Nza… you@laptop" bind:value={adding.key} oninput={() => (adding.error = '')}></textarea>
      <p class="small muted">The contents of a <code>.pub</code> file, e.g. <code>~/.ssh/id_ed25519.pub</code>. It goes into
        <span class="mono">{data.accounts.find((a) => a.user === adding.user)?.files[0] ?? '~/.ssh/authorized_keys'}</span>.</p>
      {#if adding.error}<div class="banner bad" role="alert"><Icon name="error" /><p>{adding.error}</p></div>{/if}
    </div>
    {#snippet footer()}
      <button class="btn" onclick={() => (adding.open = false)}>Cancel</button>
      <button class="btn primary" disabled={busy || !adding.user || !adding.key.trim()} onclick={add}>Add key</button>
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

  .account { display: inline-flex; align-items: center; gap: var(--space-xs); }
  .root { color: var(--warn); }
  header .hint { display: inline-flex; flex-wrap: wrap; align-items: center; gap: var(--space-sm); }
  td .pill { margin-left: var(--space-2xs); }
  .fp { display: inline-flex; align-items: center; gap: var(--space-2xs); }
  .fp .mono { overflow-wrap: anywhere; }
  .comment { overflow-wrap: anywhere; }
  .others { margin: 0; }
  @media (max-width: 640px) { .files { display: none; } }

  .stack-sm { display: flex; flex-direction: column; gap: var(--space-xs); }
  .stack-sm p { margin: 0; }
  textarea { resize: vertical; overflow-wrap: anywhere; }
  .banner .spinner { margin-top: 4px; }
  .spinner { display: inline-block; flex: none; width: 12px; height: 12px; border: 2px solid var(--color-rule-2); border-top-color: var(--color-accent); border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .spinner { animation: none; } }

  .output > summary { width: fit-content; cursor: pointer; font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--color-ink-2); }
  .output > summary:hover { color: var(--text-strong); }
  .output[open] > summary { margin-bottom: var(--space-xs); }
  .notes ul { margin: 0; padding-left: var(--space-md); }
</style>
