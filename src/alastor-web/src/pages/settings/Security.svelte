<script lang="ts">
  import { api, type SelfCheck } from '../../lib/api';
  import Icon from '../../lib/ui/Icon.svelte';

  let checks = $state<SelfCheck[] | null>(null);
  let failed = $state(false);

  const load = () =>
    api<SelfCheck[]>('/api/system/security')
      .then((c) => (checks = c))
      .catch(() => (failed = true));
  $effect(() => {
    load();
  });

  const order: Record<SelfCheck['status'], number> = { Fail: 0, Warn: 1, Info: 2, Pass: 3 };
  const sorted = $derived([...(checks ?? [])].sort((a, b) => order[a.status] - order[b.status]));
  const counts = $derived({
    fail: checks?.filter((c) => c.status === 'Fail').length ?? 0,
    warn: checks?.filter((c) => c.status === 'Warn').length ?? 0,
  });
  const look = { Pass: { icon: 'check', cls: 'ok' }, Info: { icon: 'info', cls: 'info' }, Warn: { icon: 'alert', cls: 'warn' }, Fail: { icon: 'error', cls: 'bad' } } as const;
</script>

<section class="card">
  <header>
    <h2>Security self-check</h2>
    <span class="hint">{#if checks}{counts.fail ? `${counts.fail} failing` : counts.warn ? `${counts.warn} to look at` : 'all good'}{/if}</span>
  </header>
  <p class="muted small intro">
    Installing Alastor shouldn't make a server easier to attack. These checks look at the server itself: where it listens, who can reach it, whether
    traffic is encrypted, and how its secrets are stored. Most fixes are server settings (environment variables), or re-running the installer with
    <code>--access tailscale</code>.
  </p>
  {#if failed}
    <div class="card-body"><div class="banner bad"><Icon name="error" /><p>Couldn't run the self-check.</p></div></div>
  {:else if checks}
    <ul class="checks">
      {#each sorted as c (c.id)}
        <li class={look[c.status].cls}>
          <span class="mark"><Icon name={look[c.status].icon} /></span>
          <div>
            <div class="title">{c.title}</div>
            <p class="detail">{c.detail}</p>
            {#if c.fix && (c.status === 'Warn' || c.status === 'Fail')}<p class="fix"><strong>Fix:</strong> {c.fix}</p>{/if}
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .intro { margin: 0; padding: var(--space-sm) var(--space-md); max-width: 80ch; line-height: 1.6; }
  .checks { list-style: none; margin: 0; padding: 0; border-top: var(--rule-hair) solid var(--border); }
  .checks li { display: grid; grid-template-columns: 24px minmax(0, 1fr); gap: var(--space-sm); padding: var(--space-sm) var(--space-md); border-bottom: var(--rule-hair) solid var(--border); }
  .checks li:last-child { border-bottom: 0; }
  .mark { display: grid; place-items: center; height: 22px; }
  .ok .mark { color: var(--ok); }
  .info .mark { color: var(--muted); }
  .warn .mark { color: var(--warn); }
  .bad .mark { color: var(--bad); }
  .title { font-family: var(--font-display); font-weight: 500; color: var(--text-strong); }
  .detail, .fix { margin: var(--space-3xs) 0 0; max-width: 85ch; overflow-wrap: anywhere; }
  .detail { color: var(--color-ink-2); }
  .fix { font-size: var(--text-sm); }
  .banner > :global(.icon) { margin-top: var(--space-3xs); color: var(--bad); }
</style>
