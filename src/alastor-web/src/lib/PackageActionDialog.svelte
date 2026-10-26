<script lang="ts">
  import { api, errorText, type Command, type PackagePlan, type PackagePlanResult, type SoftwarePackage } from './api';
  import FixCommands from './FixCommands.svelte';
  import { on } from './live.svelte';
  import { toast } from './toast.svelte';
  import Icon from './ui/Icon.svelte';
  import Modal from './ui/Modal.svelte';

  let {
    open = $bindable(false),
    hostId,
    hostName,
    isOnline,
    pkg,
    op,
    onQueued,
  }: {
    open?: boolean;
    hostId: string;
    hostName: string;
    isOnline: boolean;
    pkg: SoftwarePackage | null;
    op: 'upgrade' | 'remove';
    onQueued?: (op: 'upgrade' | 'remove', name: string) => void;
  } = $props();

  let phase = $state<'idle' | 'asking' | 'ready' | 'failed'>('idle');
  let plan = $state<PackagePlan | null>(null);
  let failure = $state('');
  let busy = $state(false);

  const verb = $derived(op === 'upgrade' ? 'Upgrade' : 'Uninstall');
  const manual = $derived(pkg ? (op === 'upgrade' ? pkg.upgradeCommand : pkg.removeCommand) : null);
  const others = $derived(plan?.changes.filter((c) => c.name !== pkg?.name) ?? []);
  const nothingToDo = $derived(plan?.success === true && plan.changes.length === 0);
  const canApply = $derived(phase === 'ready' && !!plan?.success && plan.blocked.length === 0 && plan.changes.length > 0 && !busy);

  // Ask the agent for a dry run whenever the dialog opens. The answer arrives as a finished command.
  $effect(() => {
    if (!open || !pkg) return;
    const name = pkg.name;
    plan = null;
    failure = '';
    if (!isOnline) {
      phase = 'failed';
      failure = `${hostName} is offline, so it can't show what would change. Run the command below on the host, or try again when it's back.`;
      return;
    }
    phase = 'asking';
    let commandId = '';
    let cancelled = false;
    const started = Date.now();

    async function fetchPlan() {
      if (!commandId || cancelled) return;
      try {
        const r = await api<PackagePlanResult>(`/api/hosts/${hostId}/software/plan/${commandId}`);
        if (cancelled) return;
        if (r.status === 'Pending' || r.status === 'Delivered') {
          if (Date.now() - started > 120_000) { phase = 'failed'; failure = 'The host didn\'t answer within two minutes.'; }
          return;
        }
        if (r.plan) { plan = r.plan; phase = r.plan.success ? 'ready' : 'failed'; failure = r.plan.error ?? ''; }
        else { phase = 'failed'; failure = r.message ?? 'The agent returned no dry run. It may be older than this server; update it first.'; }
      } catch (e) {
        if (!cancelled) { phase = 'failed'; failure = errorText(e); }
      }
    }

    const off = on('commandUpdated', (c: Command) => { if (c.id === commandId) fetchPlan(); });
    const poll = setInterval(() => { if (phase === 'asking') fetchPlan(); }, 3000); // in case the live connection is down
    api<Command>(`/api/hosts/${hostId}/software/plan`, { method: 'POST', body: JSON.stringify({ op, package: name }) })
      .then((c) => { commandId = c.id; })
      .catch((e) => { if (!cancelled) { phase = 'failed'; failure = errorText(e); } });
    return () => { cancelled = true; off(); clearInterval(poll); };
  });

  async function apply() {
    if (!pkg) return;
    busy = true;
    try {
      await api<Command>(`/api/hosts/${hostId}/software/${op}`, { method: 'POST', body: JSON.stringify({ package: pkg.name }) });
      toast(`${op === 'upgrade' ? 'Upgrade' : 'Uninstall'} of ${pkg.name} queued. This page updates when the agent reports back.`);
      onQueued?.(op, pkg.name);
      open = false;
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      busy = false;
    }
  }

  const actionTone: Record<string, string> = { upgrade: 'info', install: 'muted', downgrade: 'warn', remove: 'bad' };
</script>

<Modal bind:open title={pkg ? `${verb} ${pkg.name}` : verb} wide>
  {#if pkg}
    <div class="stack-sm">
      {#if op === 'upgrade'}
        <p>
          Upgrades <span class="mono">{pkg.name}</span> on {hostName} from <span class="mono">{pkg.version}</span>{#if pkg.candidate} to <span class="mono">{pkg.candidate}</span>{/if}
          with the host's package manager{pkg.security ? ', from a security repository' : ''}. Locally changed config files are kept. Services may restart; the host is never rebooted.
        </p>
      {:else}
        <p>
          Removes <span class="mono">{pkg.name}</span> <span class="mono muted">{pkg.version}</span> from {hostName}.
          {#if pkg.manual}It was installed on purpose, so check nothing on the host still needs it.{:else}It was installed as a dependency of another package.{/if}
        </p>
      {/if}

      <section class="plan" aria-live="polite">
        <h3>Dry run on {hostName}</h3>
        {#if phase === 'asking'}
          <p class="muted small waiting"><span class="spinner" aria-hidden="true"></span> Asking the host what would change…</p>
        {:else if phase === 'failed'}
          <div class="banner warn"><Icon name="alert" /><p>{failure}</p></div>
        {:else if plan}
          {#if plan.blocked.length}
            <div class="banner bad" role="alert">
              <Icon name="error" />
              <p><strong>Blocked.</strong> This would remove {plan.blocked.length === 1 ? 'a protected package' : 'protected packages'}: <span class="mono">{plan.blocked.join(', ')}</span>.
                Removing {plan.blocked.length === 1 ? 'it' : 'them'} could leave the host unbootable or unreachable, so the agent refuses. Do it at the console if you're sure.</p>
            </div>
          {/if}
          {#if nothingToDo}
            <p class="small">{op === 'upgrade' ? `${pkg.name} is already the newest version the host's repositories offer.` : 'The package manager says there is nothing to remove.'}</p>
          {:else}
            {#if others.length && !plan.blocked.length}
              <p class="small" class:warn-text={op === 'remove'}>
                {others.length} other package{others.length === 1 ? '' : 's'} would change too{op === 'remove' && others.some((c) => c.action === 'remove') ? ', including packages that depend on it' : ''}.
              </p>
            {/if}
            <div class="table-wrap changes">
              <table class="table">
                <thead><tr><th>Change</th><th>Package</th><th class="hide-sm">From</th>{#if plan.changes.some((c) => c.to)}<th>To</th>{/if}</tr></thead>
                <tbody>
                  {#each plan.changes as c (c.name + c.action)}
                    <tr>
                      <td><span class="pill {actionTone[c.action] ?? 'muted'}">{c.action}</span></td>
                      <td class="mono small">{c.name}{#if plan.blocked.includes(c.name)} <span class="pill bad">protected</span>{/if}</td>
                      <td class="mono small muted hide-sm">{c.from ?? ''}</td>
                      {#if plan.changes.some((x) => x.to)}<td class="mono small">{c.to ?? ''}</td>{/if}
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        {/if}
      </section>

      {#if manual}
        <section class="by-hand" aria-label="Run it yourself">
          <h3>Or run it yourself</h3>
          <FixCommands groups={[{ hosts: [], commands: [manual] }]} tab="software" />
        </section>
      {/if}
    </div>
  {/if}
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Cancel</button>
    <button class="btn {op === 'remove' ? 'solid-danger' : 'primary'}" onclick={apply} disabled={!canApply}>
      {busy ? 'Queuing…' : phase === 'asking' ? 'Waiting for dry run…' : verb}
    </button>
  {/snippet}
</Modal>

<style>
  .stack-sm { display: flex; flex-direction: column; gap: var(--space-sm); }
  .stack-sm p { margin: 0; }
  h3 { margin: 0; font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--text-strong); }
  .plan, .by-hand { display: flex; flex-direction: column; gap: var(--space-xs); padding-top: var(--space-sm); border-top: var(--rule-hair) solid var(--border); }
  .changes { max-height: 280px; overflow: auto; }
  .waiting { display: inline-flex; align-items: center; gap: var(--space-xs); }
  .spinner { width: 12px; height: 12px; border: 2px solid var(--color-rule-2); border-top-color: var(--color-accent); border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .spinner { animation: none; } }
  .warn-text { color: var(--warn); }
</style>
