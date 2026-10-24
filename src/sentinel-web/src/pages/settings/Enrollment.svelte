<script lang="ts">
  import { api, errorText, type EnrollmentToken } from '../../lib/api';
  import { fleet, hostNames } from '../../lib/fleet.svelte';
  import { toast } from '../../lib/toast.svelte';
  import CopyButton from '../../lib/ui/CopyButton.svelte';
  import Time from '../../lib/ui/Time.svelte';

  let tokens = $state<EnrollmentToken[]>([]);
  let note = $state('');
  let groupId = $state('');
  let tags = $state('');
  let ttlHours = $state('');
  let busy = $state(false);
  let created = $state<{ secret: string; installCommand: string; token: EnrollmentToken } | null>(null);

  async function load() {
    tokens = await api<EnrollmentToken[]>('/api/enrollment-tokens').catch(() => tokens);
  }
  $effect(() => {
    load();
  });

  async function create(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    try {
      created = await api('/api/enrollment-tokens', {
        method: 'POST',
        body: JSON.stringify({
          note: note.trim() || null,
          groupId: groupId || null,
          tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
          ttlHours: ttlHours ? Number(ttlHours) : null,
        }),
      });
      note = '';
      tags = '';
      load();
    } catch (err) {
      toast(errorText(err), 'error');
    } finally {
      busy = false;
    }
  }

  async function revoke(t: EnrollmentToken) {
    try {
      await api(`/api/enrollment-tokens/${t.id}`, { method: 'DELETE' });
      toast('Token revoked.');
      load();
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  const server = location.origin;
  const manual = $derived(created ? `sudo sentinel-agent enroll --server ${server} --token ${created.secret}${server.startsWith('http:') ? ' --insecure' : ''}` : '');
  const status = (t: EnrollmentToken) => (t.consumedAt ? 'used' : new Date(t.expiresAt).getTime() < Date.now() ? 'expired' : 'active');
</script>

<div class="stack">
  {#if created}
    <section class="card created">
      <header><h2>Token created</h2><button class="btn small" onclick={() => (created = null)}>Done</button></header>
      <div class="card-body stack">
        <div class="banner warn"><p>This is the only time the token is shown. It works once and expires <Time iso={created.token.expiresAt} />.</p></div>
        <div>
          <div class="lbl">Run on the new server</div>
          <div class="cmd"><pre class="mono">{created.installCommand}</pre><CopyButton text={created.installCommand} /></div>
          <p class="muted small">The one-line installer ships with deliverable 10. Until then, copy the agent binary to the server and enroll it directly:</p>
          <div class="cmd"><pre class="mono">{manual}</pre><CopyButton text={manual} /></div>
          <p class="muted small">then <code>sudo systemctl enable --now sentinel-agent</code>. The host appears under <a href="/hosts">Hosts</a> within a minute.</p>
        </div>
      </div>
    </section>
  {/if}

  <section class="card">
    <header><h2>New enrollment token</h2></header>
    <form class="card-body form" onsubmit={create}>
      <div class="row">
        <label>Note <input class="field" bind:value={note} maxlength="200" placeholder="web-3 at Hetzner" /></label>
        <label>
          Group
          <select class="field" bind:value={groupId}>
            <option value="">No group</option>
            {#each fleet.groups as g (g.id)}<option value={g.id}>{g.name}</option>{/each}
          </select>
        </label>
      </div>
      <div class="row">
        <label>Tags <input class="field" bind:value={tags} placeholder="web, production" /></label>
        <label>Valid for <span class="muted small">(hours, 1–720; empty = server default)</span><input class="field" type="number" min="1" max="720" bind:value={ttlHours} placeholder="24" /></label>
      </div>
      <p class="help">The host joins the group and gets the tags on enrollment. Tokens are single-use and stored only as a hash.</p>
      <div class="form-actions"><button class="btn primary" disabled={busy}>Create token</button></div>
    </form>
  </section>

  <section class="card table-wrap">
    <header><h2>Recent tokens</h2></header>
    {#if tokens.length}
      <table class="table">
        <thead><tr><th>Note</th><th>Status</th><th class="hide-sm">Created</th><th>Expires / used</th><th></th></tr></thead>
        <tbody>
          {#each tokens as t (t.id)}
            {@const st = status(t)}
            <tr>
              <td>{t.note ?? ''}{#if t.tags.length}<div class="muted small">{t.tags.join(', ')}</div>{/if}</td>
              <td><span class="pill {st === 'active' ? 'ok' : st === 'used' ? 'info' : 'muted'}">{st}</span></td>
              <td class="hide-sm nowrap">{t.createdBy} · <Time iso={t.createdAt} /></td>
              <td class="nowrap">
                {#if t.consumedAt}
                  {#if t.consumedByHostId && hostNames()[t.consumedByHostId]}<a href="/hosts/{t.consumedByHostId}">{hostNames()[t.consumedByHostId]}</a> · {/if}<Time iso={t.consumedAt} />
                {:else}<Time iso={t.expiresAt} />{/if}
              </td>
              <td class="actions">{#if st === 'active'}<button class="btn small danger" onclick={() => revoke(t)}>Revoke</button>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <div class="empty">No tokens yet.</div>
    {/if}
  </section>
</div>

<style>
  .created { border-color: color-mix(in srgb, var(--ok) 50%, transparent); }
  .cmd { display: flex; gap: 8px; align-items: flex-start; margin: 6px 0; }
  .cmd pre { flex: 1; padding: 10px; border-radius: 6px; background: var(--bg); border: 1px solid var(--border); }
</style>
