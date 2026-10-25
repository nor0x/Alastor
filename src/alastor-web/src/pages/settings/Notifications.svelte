<script lang="ts">
  import {
    api, errorText, capabilities, severities,
    type ChannelConfig, type ChannelType, type NotificationChannel, type NotificationDelivery, type Severity, type Capability,
  } from '../../lib/api';
  import { toast } from '../../lib/toast.svelte';
  import { confirm } from '../../lib/ui/confirm.svelte';
  import Modal from '../../lib/ui/Modal.svelte';
  import Time from '../../lib/ui/Time.svelte';

  let channels = $state<NotificationChannel[]>([]);
  let deliveries = $state<NotificationDelivery[]>([]);
  let loaded = $state(false);
  let testing = $state<string | null>(null);

  async function load() {
    [channels, deliveries] = await Promise.all([
      api<NotificationChannel[]>('/api/notifications/channels').catch(() => channels),
      api<NotificationDelivery[]>('/api/notifications/deliveries?limit=30').catch(() => deliveries),
    ]);
    loaded = true;
  }
  $effect(() => {
    load();
  });

  const typeLabel: Record<ChannelType, string> = { email: 'Email', webhook: 'Webhook', ntfy: 'ntfy' };
  const target = (c: NotificationChannel) =>
    c.type === 'email' ? (c.config.to ?? []).join(', ')
    : c.type === 'webhook' ? hostOf(c.config.url) + (c.config.format && c.config.format !== 'json' ? ` (${c.config.format})` : '')
    : `${hostOf(c.config.ntfyServer ?? 'https://ntfy.sh')}/${c.config.topic}`;
  function hostOf(url: string | null | undefined) {
    try { return new URL(url ?? '').host; } catch { return url ?? ''; }
  }

  // ---- editor ----
  interface Draft {
    id: string | null;
    name: string;
    type: ChannelType;
    enabled: boolean;
    minSeverity: Severity;
    capabilities: Capability[];
    immediate: boolean;
    digest: boolean;
    digestSchedule: string;
    config: ChannelConfig;
    to: string;
    secretsSet: NotificationChannel['secretsSet'];
  }
  let draft = $state<Draft | null>(null);
  let editorOpen = $state(false);
  let saving = $state(false);
  let errors = $state<Record<string, string>>({});

  function blank(type: ChannelType): Draft {
    return {
      id: null, name: '', type, enabled: true, minSeverity: 'Medium', capabilities: [], immediate: true, digest: false, digestSchedule: '0 8 * * *',
      config: type === 'email' ? { smtpSecurity: 'starttls' } : type === 'webhook' ? { format: 'json' } : {},
      to: '', secretsSet: { smtpPassword: false, secret: false, token: false },
    };
  }
  function openNew(type: ChannelType) {
    draft = blank(type);
    errors = {};
    editorOpen = true;
  }
  function openEdit(c: NotificationChannel) {
    draft = {
      id: c.id, name: c.name, type: c.type, enabled: c.enabled, minSeverity: c.minSeverity, capabilities: [...c.capabilities],
      immediate: c.immediate, digest: c.digestSchedule !== 'off', digestSchedule: c.digestSchedule === 'off' ? '0 8 * * *' : c.digestSchedule,
      config: { ...c.config, smtpPassword: '', secret: '', token: '' }, to: (c.config.to ?? []).join(', '), secretsSet: c.secretsSet,
    };
    errors = {};
    editorOpen = true;
  }

  const body = (d: Draft, overrides: Partial<{ enabled: boolean }> = {}) => ({
    name: d.name, type: d.type, enabled: overrides.enabled ?? d.enabled, minSeverity: d.minSeverity, capabilities: d.capabilities,
    immediate: d.immediate, digestSchedule: d.digest ? d.digestSchedule.trim() : 'off',
    config: {
      ...d.config,
      to: d.type === 'email' ? d.to.split(/[,\s;]+/).map((t) => t.trim()).filter(Boolean) : null,
      smtpPort: d.config.smtpPort ? Number(d.config.smtpPort) : null,
    },
  });

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!draft) return;
    saving = true;
    errors = {};
    try {
      const saved = await api<NotificationChannel>(draft.id ? `/api/notifications/channels/${draft.id}` : '/api/notifications/channels', {
        method: draft.id ? 'PUT' : 'POST',
        body: JSON.stringify(body(draft)),
      });
      editorOpen = false;
      toast(draft.id ? 'Channel saved.' : `Channel "${saved.name}" created. Send a test to check it.`);
      await load();
    } catch (err) {
      const problem = (err as { body?: { errors?: Record<string, string[]> } }).body;
      if (problem?.errors) {
        errors = Object.fromEntries(Object.entries(problem.errors).map(([k, v]) => [k.replace(/^config\./i, ''), v.join(' ')]));
      }
      toast(errorText(err), 'error');
    } finally {
      saving = false;
    }
  }

  async function setEnabled(c: NotificationChannel, enabled: boolean) {
    try {
      await api(`/api/notifications/channels/${c.id}`, { method: 'PUT', body: JSON.stringify({ name: c.name, type: c.type, enabled, config: c.config }) });
      load();
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  async function test(c: NotificationChannel) {
    testing = c.id;
    try {
      const r = await api<{ success: boolean; error: string | null }>(`/api/notifications/channels/${c.id}/test`, { method: 'POST' });
      if (r.success) toast(`Test sent to "${c.name}".`);
      else toast(`"${c.name}" failed: ${r.error}`, 'error');
      load();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      testing = null;
    }
  }

  async function remove(c: NotificationChannel) {
    if (!(await confirm(`Delete "${c.name}"?`, 'Alerts stop going to this channel. Its delivery history is deleted too.', { confirmLabel: 'Delete', danger: true }))) return;
    try {
      await api(`/api/notifications/channels/${c.id}`, { method: 'DELETE' });
      load();
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  function toggleCap(cap: Capability) {
    if (!draft) return;
    draft.capabilities = draft.capabilities.includes(cap) ? draft.capabilities.filter((c) => c !== cap) : [...draft.capabilities, cap];
  }

  const secretHint = (set: boolean) => (set ? 'Stored. Leave empty to keep it.' : '');
</script>

<div class="stack">
  <section class="card">
    <header>
      <h2>Notification channels</h2>
      <div class="add">
        <button class="btn small" onclick={() => openNew('email')}>+ Email</button>
        <button class="btn small" onclick={() => openNew('webhook')}>+ Webhook</button>
        <button class="btn small" onclick={() => openNew('ntfy')}>+ ntfy</button>
      </div>
    </header>
    <div class="card-body">
      <p class="muted small m0">
        Every stored event at or above a channel's minimum severity is sent right away. Repeats of the same event on the same host (for
        example the same IP banned again) are sent once per dedup window and counted, and the count rides along with the next alert. A more
        severe repeat always goes out. Digests summarise everything since the last digest on a schedule.
      </p>
    </div>
    {#if channels.length}
      <ul class="channels">
        {#each channels as c (c.id)}
          <li class:disabled={!c.enabled}>
            <div class="info">
              <div class="title">
                <strong>{c.name}</strong>
                <span class="pill muted">{typeLabel[c.type]}</span>
                {#if !c.enabled}<span class="pill muted">paused</span>
                {:else if c.lastError}<span class="pill bad" title={c.lastError}>failing</span>
                {:else if c.lastSuccessAt}<span class="pill ok">working</span>{/if}
              </div>
              <div class="muted small target">{target(c)}</div>
              <div class="muted small">
                {#if c.immediate}{c.minSeverity} and above{c.capabilities.length ? ` · ${c.capabilities.join(', ')}` : ''}{:else}No immediate alerts{/if}
                {#if c.digestSchedule !== 'off'} · digest {c.digestSchedule}{#if c.nextDigestAt}, next <Time iso={c.nextDigestAt} />{/if}{/if}
              </div>
              {#if c.lastError}<div class="err small">{c.lastError}</div>{/if}
            </div>
            <div class="acts">
              <button class="btn small" disabled={testing === c.id} onclick={() => test(c)}>{testing === c.id ? 'Sending…' : 'Send test'}</button>
              <button class="btn small" onclick={() => openEdit(c)}>Edit</button>
              <button class="btn small" onclick={() => setEnabled(c, !c.enabled)}>{c.enabled ? 'Pause' : 'Resume'}</button>
              <button class="btn small danger" onclick={() => remove(c)}>Delete</button>
            </div>
          </li>
        {/each}
      </ul>
    {:else if loaded}
      <div class="empty">No channels yet. Alerts are stored and shown on the dashboard but not sent anywhere.</div>
    {/if}
  </section>

  <section class="card table-wrap">
    <header><h2>Recent deliveries</h2><span class="hint">newest first · last 1000 kept</span></header>
    {#if deliveries.length}
      <table class="table">
        <thead><tr><th>When</th><th class="hide-sm">Channel</th><th>Message</th><th class="hide-sm">Kind</th><th>Result</th></tr></thead>
        <tbody>
          {#each deliveries as d (d.id)}
            <tr>
              <td class="nowrap"><Time iso={d.at} /></td>
              <td class="nowrap hide-sm">{d.channelName}</td>
              <td class="msg"><span class="chan muted small">{d.channelName}</span>{d.title}{#if d.error}<div class="err small">{d.error}</div>{/if}</td>
              <td class="hide-sm nowrap">{d.kind}{d.eventCount > 1 ? ` · ${d.eventCount} events` : ''}</td>
              <td class="nowrap">
                {#if d.success}<span class="pill ok">sent</span>{:else}<span class="pill bad">failed</span>{/if}
                {#if d.attempts > 1}<span class="muted small">{d.attempts} tries</span>{/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <div class="empty">Nothing sent yet.</div>
    {/if}
  </section>
</div>

<Modal bind:open={editorOpen} title={draft?.id ? `Edit ${draft.name}` : `New ${draft ? typeLabel[draft.type] : ''} channel`} wide>
  {#if draft}
    <form id="channel-form" class="form" onsubmit={save}>
      <label>Name <input class="field" bind:value={draft.name} maxlength="64" required placeholder={draft.type === 'email' ? 'Ops mailbox' : draft.type === 'webhook' ? 'Slack #alerts' : 'My phone'} />
        {#if errors.name}<span class="err small">{errors.name}</span>{/if}</label>

      {#if draft.type === 'email'}
        <div class="row">
          <label class="grow">SMTP server <input class="field" bind:value={draft.config.smtpHost} required placeholder="smtp.example.com" />
            {#if errors.smtpHost}<span class="err small">{errors.smtpHost}</span>{/if}</label>
          <label>Security
            <select class="field" bind:value={draft.config.smtpSecurity}>
              <option value="starttls">STARTTLS (587)</option><option value="ssl">TLS (465)</option><option value="none">None (25)</option>
            </select></label>
          <label>Port <input class="field" type="number" min="1" max="65535" bind:value={draft.config.smtpPort} placeholder="default" /></label>
        </div>
        <div class="row">
          <label>Username <input class="field" bind:value={draft.config.smtpUsername} autocomplete="off" /></label>
          <label>Password <input class="field" type="password" bind:value={draft.config.smtpPassword} autocomplete="new-password" placeholder={draft.secretsSet.smtpPassword ? '••••••••' : ''} />
            <span class="help">{secretHint(draft.secretsSet.smtpPassword)}</span></label>
        </div>
        <label>From <input class="field" type="email" bind:value={draft.config.from} required placeholder="alastor@example.com" />
          {#if errors.from}<span class="err small">{errors.from}</span>{/if}</label>
        <label>To <input class="field" bind:value={draft.to} required placeholder="ops@example.com, me@example.com" />
          {#if errors.to}<span class="err small">{errors.to}</span>{/if}</label>
      {:else if draft.type === 'webhook'}
        <label>URL <input class="field" type="url" bind:value={draft.config.url} required placeholder="https://hooks.slack.com/services/…" />
          {#if errors.url}<span class="err small">{errors.url}</span>{/if}</label>
        <div class="row">
          <label>Format
            <select class="field" bind:value={draft.config.format}>
              <option value="json">Alastor JSON</option><option value="slack">Slack / Mattermost</option><option value="discord">Discord</option>
            </select></label>
          <label>Signing secret <input class="field" type="password" bind:value={draft.config.secret} autocomplete="new-password" placeholder={draft.secretsSet.secret ? '••••••••' : 'optional'} />
            <span class="help">{draft.secretsSet.secret ? secretHint(true) : ''}</span></label>
        </div>
        <p class="help">With a secret, each request carries <code>X-Alastor-Signature: sha256=&lt;hex HMAC of the body&gt;</code> so the receiver can check it came from this server.</p>
      {:else}
        <div class="row">
          <label>Topic <input class="field" bind:value={draft.config.topic} required maxlength="64" placeholder="alastor-k3x9q" />
            {#if errors.topic}<span class="err small">{errors.topic}</span>{/if}</label>
          <label>Server <input class="field" type="url" bind:value={draft.config.ntfyServer} placeholder="https://ntfy.sh" />
            {#if errors.ntfyServer}<span class="err small">{errors.ntfyServer}</span>{/if}</label>
        </div>
        <label>Access token <input class="field" type="password" bind:value={draft.config.token} autocomplete="new-password" placeholder={draft.secretsSet.token ? '••••••••' : 'optional, for protected topics'} />
          <span class="help">{secretHint(draft.secretsSet.token)}</span></label>
        <p class="help">Topics on the public ntfy.sh server are readable by anyone who knows the name: pick a hard-to-guess one or use your own ntfy server.</p>
      {/if}

      <fieldset>
        <legend>What to send</legend>
        <label class="check"><input type="checkbox" bind:checked={draft.immediate} /> Send alerts as they happen</label>
        <div class="row">
          <label>Minimum severity
            <select class="field" bind:value={draft.minSeverity}>{#each severities as s (s)}<option value={s}>{s}</option>{/each}</select></label>
          <label class="check"><input type="checkbox" bind:checked={draft.digest} /> Also send a digest</label>
          {#if draft.digest}
            <label>Digest schedule <input class="field mono" bind:value={draft.digestSchedule} placeholder="0 8 * * *" />
              {#if errors.digestSchedule}<span class="err small">{errors.digestSchedule}</span>{/if}</label>
          {/if}
        </div>
        {#if errors.immediate}<span class="err small">{errors.immediate}</span>{/if}
        <div class="lbl">Only these capabilities <span class="small">(none selected = all)</span></div>
        <div class="caps">
          {#each capabilities as cap (cap)}
            <label class="check cap"><input type="checkbox" checked={draft.capabilities.includes(cap)} onchange={() => toggleCap(cap)} /> {cap}</label>
          {/each}
        </div>
        <p class="help">Schedules use the same syntax as policies: an interval like <code>every 12h</code> or a cron expression like <code>0 8 * * 1-5</code> (08:00 on weekdays), in the server's time zone.</p>
      </fieldset>
    </form>
  {/if}
  {#snippet footer()}
    <button class="btn" type="button" onclick={() => (editorOpen = false)}>Cancel</button>
    <button class="btn primary" form="channel-form" disabled={saving}>{draft?.id ? 'Save' : 'Create channel'}</button>
  {/snippet}
</Modal>

<style>
  .m0 { margin: 0; }
  .add { display: flex; gap: 6px; flex-wrap: wrap; }
  .channels { list-style: none; margin: 0; padding: 0; border-top: 1px solid var(--border); }
  .channels li { display: flex; gap: 12px 16px; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; padding: 12px 16px; border-bottom: 1px solid var(--border); }
  .channels li:last-child { border-bottom: 0; }
  .channels li.disabled .info { opacity: 0.6; }
  .info { display: flex; flex-direction: column; gap: 3px; min-width: 0; flex: 1 1 280px; }
  .title { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .target { overflow-wrap: anywhere; }
  .acts { display: flex; gap: 6px; flex-wrap: wrap; }
  .err { color: var(--bad); overflow-wrap: anywhere; }
  .msg { overflow-wrap: anywhere; min-width: 180px; }
  .chan { display: none; }
  @media (max-width: 640px) { .chan { display: block; } }
  .grow { flex: 2 1 220px !important; }
  fieldset { border: 1px solid var(--border); border-radius: var(--radius); padding: 10px 14px 14px; margin: 0; display: flex; flex-direction: column; gap: 12px; }
  legend { color: var(--text-strong); font-size: 13px; padding: 0 4px; }
  .row .check { align-self: flex-end; padding-bottom: 8px; }
  .caps { display: flex; flex-wrap: wrap; gap: 6px 16px; }
  .cap { font-size: 13px; }
</style>
