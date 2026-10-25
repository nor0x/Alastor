<script lang="ts">
  import { errorText } from './api';
  import { fixValue, layerHref, setLayerKey, type BaselineCheck, type ScopeOption } from './baseline';
  import { toast } from './toast.svelte';
  import Modal from './ui/Modal.svelte';

  let {
    open = $bindable(false),
    check,
    scopes,
    onDone,
  }: { open?: boolean; check: BaselineCheck | null; scopes: ScopeOption[]; onDone?: () => void } = $props();

  let choice = $state('');
  let busy = $state(false);
  $effect(() => {
    if (open) choice = scopes[0]?.key ?? '';
  });

  const selected = $derived(scopes.find((s) => s.key === choice));
  const yamlLine = $derived(check ? `${check.policyPath.join('.')}: ${check.policyValue}` : '');
  const where = $derived.by(() => {
    if (!check) return '';
    if (check.category === 'Ssh' && check.policyPath[0] === 'baseline')
      return 'The agent writes /etc/ssh/sshd_config.d/01-alastor.conf, checks it with "sshd -t", and reloads sshd. If sshd rejects it, the file is rolled back.';
    if (check.policyPath[0] === 'baseline')
      return 'The agent writes /etc/sysctl.d/99-zz-alastor.conf and loads it. Removing the fix later restores the previous values.';
    return 'The agent enables the sshd jail and installs or adopts fail2ban from the distribution packages.';
  });

  async function apply() {
    if (!check || !selected) return;
    busy = true;
    try {
      const v = await setLayerKey(selected.layer, check.policyPath, fixValue(check), `Baseline: apply "${check.title}"`);
      toast(`Fix saved in the ${selected.label.toLowerCase()} policy (v${v.version}). Agents apply it within seconds and re-check.`);
      open = false;
      onDone?.();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      busy = false;
    }
  }
</script>

<Modal bind:open title={check ? `Apply fix: ${check.title}` : 'Apply fix'}>
  {#if check}
    <div class="stack-sm">
      <p>{check.remediation}</p>
      <p class="muted small">{where}</p>
      <fieldset class="scopes">
        <legend>Where</legend>
        {#each scopes as s (s.key)}
          <label class="scope" class:on={choice === s.key}>
            <input type="radio" name="fix-scope" value={s.key} bind:group={choice} />
            <span><strong>{s.label}</strong><span class="muted small">{s.help}</span></span>
          </label>
        {/each}
      </fieldset>
      {#if selected}
        <p class="small">
          Adds <code>{yamlLine}</code> to the <a href={layerHref(selected.layer)}>{selected.label.toLowerCase()} policy</a> as a new version you can revert.
        </p>
      {/if}
    </div>
  {/if}
  {#snippet footer()}
    <button class="btn" onclick={() => (open = false)}>Cancel</button>
    <button class="btn primary" onclick={apply} disabled={busy || !selected}>{busy ? 'Saving…' : 'Apply fix'}</button>
  {/snippet}
</Modal>

<style>
  .stack-sm { display: flex; flex-direction: column; gap: 10px; }
  .stack-sm p { margin: 0; }
  .scopes { border: 0; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
  .scopes legend { font-size: 12px; color: var(--muted); margin-bottom: 4px; }
  .scope { display: flex; gap: 10px; align-items: flex-start; padding: 8px 10px; border: 1px solid var(--border); border-radius: var(--radius); cursor: pointer; }
  .scope.on { border-color: var(--link); background: var(--surface-2); }
  .scope input { margin-top: 3px; }
  .scope span { display: flex; flex-direction: column; gap: 2px; }
</style>
