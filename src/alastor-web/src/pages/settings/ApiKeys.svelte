<script lang="ts">
  import { api, errorText, type ApiKey } from '../../lib/api';
  import { toast } from '../../lib/toast.svelte';
  import { confirm } from '../../lib/ui/confirm.svelte';
  import CopyButton from '../../lib/ui/CopyButton.svelte';
  import Icon from '../../lib/ui/Icon.svelte';
  import Time from '../../lib/ui/Time.svelte';

  let keys = $state<ApiKey[]>([]);
  let name = $state('');
  let created = $state<{ key: ApiKey; secret: string } | null>(null);

  const load = async () => (keys = await api<ApiKey[]>('/api/api-keys').catch(() => keys));
  $effect(() => {
    load();
  });

  async function create(e: SubmitEvent) {
    e.preventDefault();
    try {
      created = await api('/api/api-keys', { method: 'POST', body: JSON.stringify({ name: name.trim() }) });
      name = '';
      load();
    } catch (err) {
      toast(errorText(err), 'error');
    }
  }

  async function revoke(k: ApiKey) {
    if (!(await confirm(`Revoke "${k.name}"?`, 'Anything using this key gets 401 from now on.', { confirmLabel: 'Revoke', danger: true }))) return;
    try {
      await api(`/api/api-keys/${k.id}`, { method: 'DELETE' });
      load();
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }

  const example = $derived(created ? `curl -H 'X-Api-Key: ${created.secret}' ${location.origin}/api/overview` : '');
</script>

<div class="stack">
  <section class="card">
    <header><h2>API keys</h2><span class="hint">read-only</span></header>
    <div class="card-body stack">
      <p class="muted small m0">Keys can read everything the dashboard shows (for Grafana, scripts or status pages) but can't change anything. The full API is described at <a href="/openapi/v1.json" target="_blank" rel="noopener">/openapi/v1.json</a>.</p>
      {#if created}
        <div class="created">
          <div class="banner ok"><Icon name="check" /><p><strong>{created.key.name}</strong>: copy the key now. It isn't shown again.</p></div>
          <div class="cmd"><code>{created.secret}</code><CopyButton text={created.secret} /></div>
          <div class="cmd"><code>{example}</code><CopyButton text={example} label="Copy example" /></div>
        </div>
      {/if}
      <form class="add" onsubmit={create}>
        <input class="field" bind:value={name} maxlength="64" placeholder="Key name, e.g. grafana" required aria-label="Key name" />
        <button class="btn primary">Create key</button>
      </form>
    </div>
    {#if keys.length}
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th>Name</th><th>Prefix</th><th class="hide-sm">Created</th><th>Last used</th><th></th></tr></thead>
          <tbody>
            {#each keys as k (k.id)}
              <tr class:revoked={k.revokedAt}>
                <td><span class="kname">{k.name}</span> {#if k.revokedAt}<span class="pill muted">revoked</span>{/if}</td>
                <td class="mono">{k.prefix}…</td>
                <td class="hide-sm nowrap"><span class="pair"><span>{k.createdBy}</span><span><Time iso={k.createdAt} /></span></span></td>
                <td class="nowrap"><Time iso={k.lastUsedAt} /></td>
                <td class="actions">{#if !k.revokedAt}<button class="btn small danger" onclick={() => revoke(k)}>Revoke</button>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
</div>

<style>
  .m0 { margin: 0; max-width: 75ch; }
  .created { display: flex; flex-direction: column; gap: var(--space-xs); }
  .banner > :global(.icon) { margin-top: var(--space-3xs); color: var(--ok); }
  .add { display: flex; gap: var(--space-xs); flex-wrap: wrap; }
  .add input { flex: 1 1 220px; max-width: 420px; }
  .kname { font-weight: 500; color: var(--text-strong); }
  .pair { display: inline-flex; align-items: center; gap: var(--space-xs); }
  .pair > * + * { padding-left: var(--space-xs); border-left: var(--rule-hair) solid var(--border-strong); }
  .revoked td { color: var(--muted); }
</style>
