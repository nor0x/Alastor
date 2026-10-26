<script lang="ts">
  import { api, errorText, type Ban } from './api';
  import { canWrite } from './session.svelte';
  import { toast } from './toast.svelte';
  import { confirm } from './ui/confirm.svelte';
  import Time from './ui/Time.svelte';
  import { expires } from './format';
  import { clock } from './ui/clock.svelte';

  let { bans, showHost = true }: { bans: Ban[]; showHost?: boolean } = $props();

  async function unban(b: Ban, everywhere: boolean) {
    const where = everywhere ? 'every host' : b.hostName;
    if (!(await confirm(`Unban ${b.target}?`, `Removes the ban on ${where}. The banning engine can ban it again if it keeps misbehaving.`, { confirmLabel: 'Unban' }))) return;
    try {
      await api('/api/bans/unban', { method: 'POST', body: JSON.stringify({ target: b.target, hostIds: everywhere ? null : [b.hostId] }) });
      toast(`Unban for ${b.target} sent to ${where}.`);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }
</script>

<table class="table">
  <thead>
    <tr>
      <th>Target</th>
      {#if showHost}<th>Host</th>{/if}
      <th>Jail</th>
      <th class="hide-sm">Banned</th>
      <th>Expires</th>
      {#if canWrite()}<th><span class="visually-hidden">Actions</span></th>{/if}
    </tr>
  </thead>
  <tbody>
    {#each bans as b (b.id)}
      <tr>
        <td class="mono"><a href="/events?ip={encodeURIComponent(b.target)}" title="Events for this IP">{b.target}</a></td>
        {#if showHost}<td><a href="/hosts/{b.hostId}">{b.hostName}</a></td>{/if}
        <td>
          <span class="mono small">{b.scope}</span>
          {#if b.manual}<span class="pill info">manual</span>{/if}
        </td>
        <td class="hide-sm nowrap"><Time iso={b.bannedAt} empty="unknown" /></td>
        <td class="nowrap" class:muted={!b.expiresAt}>{expires(b.expiresAt, clock.now)}</td>
        {#if canWrite()}
          <td class="actions">
            <button class="btn small" onclick={() => unban(b, false)}>Unban</button>
            {#if showHost}<button class="btn small ghost" onclick={() => unban(b, true)} title="Unban on every host">everywhere</button>{/if}
          </td>
        {/if}
      </tr>
    {/each}
  </tbody>
</table>
