<script lang="ts">
  import { api, errorText, type LocalMachine, type MachineService } from '../../lib/api';
  import { toast } from '../../lib/toast.svelte';
  import { confirm } from '../../lib/ui/confirm.svelte';
  import CopyButton from '../../lib/ui/CopyButton.svelte';
  import Time from '../../lib/ui/Time.svelte';

  type Target = 'server' | 'agent';
  type Action = 'start' | 'stop' | 'restart';

  let machine = $state<LocalMachine | null>(null);
  let busy = $state('');
  // After a stop or restart of the server, this page can't ask it anything until it's back.
  let serverGone = $state<'stopped' | 'restarting' | null>(null);

  const load = async () => (machine = await api<LocalMachine>('/api/system/machine').catch(() => machine));
  $effect(() => {
    load();
  });

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const words: Record<string, string> = { active: 'running', inactive: 'stopped', failed: 'failed', activating: 'starting', deactivating: 'stopping', reloading: 'reloading' };
  const tone = (s: MachineService) => (s.state === 'active' ? 'ok' : s.state === 'failed' ? 'bad' : s.state === 'unknown' ? 'muted' : 'warn');

  async function act(target: Target, action: Action) {
    const host = machine?.hostname ?? 'the machine';
    if (target === 'server' && action === 'stop') {
      const ok = await confirm(
        'Stop the Alastor server?',
        `The dashboard goes offline and agents can't report until it's back. Start it again on ${host} with: sudo alastor start server`,
        { confirmLabel: 'Stop server', danger: true },
      );
      if (!ok) return;
    }
    if (target === 'agent' && action === 'stop') {
      const ok = await confirm(
        'Stop the agent on this machine?',
        `${host} stops reporting, and nothing on it is scanned or kept in line with its policy until the agent starts again. Tools it set up (fail2ban, the firewall) keep running.`,
        { confirmLabel: 'Stop agent', danger: true },
      );
      if (!ok) return;
    }
    busy = `${target}-${action}`;
    try {
      await api(`/api/system/machine/${target}/${action}`, { method: 'POST' });
      if (target === 'server') {
        serverGone = action === 'stop' ? 'stopped' : 'restarting';
        if (action === 'restart') waitForRestart(machine?.serverStartedAt ?? '');
      } else {
        toast(`Agent ${action === 'start' ? 'starting' : action === 'stop' ? 'stopping' : 'restarting'}.`);
        await sleep(1500);
        await load();
        setTimeout(load, 5000);
      }
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      busy = '';
    }
  }

  // The server is back once it answers with a new start time.
  async function waitForRestart(startedAt: string) {
    for (let i = 0; i < 60; i++) {
      await sleep(1500);
      const m = await api<LocalMachine>('/api/system/machine').catch(() => null);
      if (m && m.serverStartedAt !== startedAt) {
        machine = m;
        serverGone = null;
        toast('The server restarted.');
        return;
      }
    }
    toast(`The server isn't back after a minute. Check it on ${machine?.hostname ?? 'the machine'}: sudo alastor status`, 'error');
  }
</script>

<section class="card">
  <header><h2>This machine</h2><span class="hint">{machine?.hostname ?? ''}</span></header>
  {#if serverGone === 'stopped'}
    <div class="card-body stack">
      <p class="m0">The server is stopping, so the dashboard goes offline. Start it again on <strong>{machine?.hostname}</strong>:</p>
      <div class="cmd"><code>sudo alastor start server</code><CopyButton text="sudo alastor start server" /></div>
    </div>
  {:else if machine}
    <ul class="services">
      <li>
        <div>
          <div class="title">Server <span class="pill {serverGone === 'restarting' ? 'warn' : tone(machine.server)}">{serverGone === 'restarting' ? 'restarting' : 'running'}</span></div>
          <p class="muted small m0">
            Started <Time iso={machine.serverStartedAt} />{#if machine.server.installed}{machine.server.startsAtBoot ? ', starts at boot' : ', off at boot'}{/if}.
          </p>
        </div>
        {#if machine.controllable && machine.server.installed}
          <div class="actions-row">
            <button class="btn small" disabled={!!busy || !!serverGone} onclick={() => act('server', 'restart')}>{serverGone === 'restarting' ? 'Restarting…' : 'Restart'}</button>
            <button class="btn small danger" disabled={!!busy || !!serverGone} onclick={() => act('server', 'stop')}>Stop</button>
          </div>
        {/if}
      </li>
      <li>
        <div>
          <div class="title">
            Agent
            {#if machine.agent.installed}<span class="pill {tone(machine.agent)}">{words[machine.agent.state] ?? machine.agent.state}</span>
            {:else}<span class="pill muted">not installed</span>{/if}
          </div>
          <p class="muted small m0">
            {#if !machine.agent.installed}
              This machine isn't protected by Alastor itself. Enroll it like any other server (Settings → Enrollment).
            {:else}
              {machine.agent.startsAtBoot ? 'Starts at boot' : 'Off at boot'}{#if machine.agentHostId}; reports as <a href="/hosts/{machine.agentHostId}">{machine.agentHostName}</a>{#if machine.agentOnline === false} (offline){/if}{/if}.
            {/if}
          </p>
        </div>
        {#if machine.controllable && machine.agent.installed}
          <div class="actions-row">
            {#if machine.agent.state !== 'active'}
              <button class="btn small" disabled={!!busy || !!serverGone} onclick={() => act('agent', 'start')}>{busy === 'agent-start' ? 'Starting…' : 'Start'}</button>
            {:else}
              <button class="btn small" disabled={!!busy || !!serverGone} onclick={() => act('agent', 'restart')}>{busy === 'agent-restart' ? 'Restarting…' : 'Restart'}</button>
              <button class="btn small danger" disabled={!!busy || !!serverGone} onclick={() => act('agent', 'stop')}>Stop</button>
            {/if}
          </div>
        {/if}
      </li>
    </ul>
    <p class="muted small intro">
      {#if machine.controllable}
        From a shell on {machine.hostname}: <code>alastor status</code>, <code>sudo alastor start</code>, <code>sudo alastor stop</code> or
        <code>sudo alastor restart</code>, each optionally with <code>server</code> or <code>agent</code>. A stopped service starts again at the next
        boot; <code>sudo alastor disable</code> keeps it off.
      {:else}
        Starting and stopping from here needs the server installed with install.sh under systemd. In Docker, use <code>docker compose stop</code> and
        <code>docker compose start</code>; elsewhere, the service manager that runs the server.
      {/if}
    </p>
  {/if}
</section>

<style>
  .m0 { margin: 0; max-width: 80ch; }
  .intro { margin: 0; padding: var(--space-sm) var(--space-md); max-width: 80ch; line-height: 1.6; }
  .services { list-style: none; margin: 0; padding: 0; border-bottom: var(--rule-hair) solid var(--border); }
  .services li { display: flex; gap: var(--space-md); align-items: center; justify-content: space-between; flex-wrap: wrap; padding: var(--space-sm) var(--space-md); border-bottom: var(--rule-hair) solid var(--border); }
  .services li:last-child { border-bottom: 0; }
  .title { display: flex; align-items: center; gap: var(--space-xs); font-family: var(--font-display); font-weight: 500; color: var(--text-strong); }
  .actions-row { display: flex; gap: var(--space-xs); flex-wrap: wrap; }
  .cmd { display: flex; align-items: center; gap: var(--space-xs); flex-wrap: wrap; }
</style>
