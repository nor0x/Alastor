<script lang="ts">
  import type { Snippet } from 'svelte';
  import Logo from './Logo.svelte';

  let { size = 20, placement = 'below', label }: {
    size?: number;
    placement?: 'below' | 'inline';
    label: Snippet;
  } = $props();

  const phrase = 'Constant Vigilance!';
  const smokeId = $props.id();
  let active = $state(false);
  let replay = $state(0);
  let timeout: ReturnType<typeof setTimeout> | undefined;

  function activate() {
    clearTimeout(timeout);
    replay += 1;
    active = true;
    timeout = setTimeout(() => { active = false; }, 3000);
  }

  $effect(() => () => clearTimeout(timeout));
</script>

<div class="brand-space" class:inline-space={placement === 'inline'}>
<div class="branding" class:inline={placement === 'inline'}>
  <button type="button" class="logo-button" aria-label="Constant Vigilance!" title="Constant Vigilance!" onclick={activate}>
    <Logo {size} />
  </button>
  <div class="label">{@render label()}</div>
  <div class="spell-slot" aria-hidden="true">
    {#if active}
      {#key replay}
        <span class="spell" data-text={phrase} style:--smoke-filter={`url(#${smokeId})`}>
          {#each [...phrase] as character, index}
            <span class="letter" style:--index={index} style:--drift={`${((index * 7) % 19) - 9}px`} style:--turn={`${((index * 11) % 25) - 12}deg`}>{character}</span>
          {/each}
        </span>
      {/key}
    {/if}
  </div>
  <span class="visually-hidden" aria-live="polite" aria-atomic="true">{#if active}{#key replay}<span>Constant Vigilance!</span>{/key}{/if}</span>
</div>
<svg class="effect-definitions" aria-hidden="true" focusable="false">
  <defs>
    <filter id={smokeId} x="-60%" y="-150%" width="220%" height="400%" color-interpolation-filters="sRGB">
      <feTurbulence type="fractalNoise" baseFrequency="0.035 0.09" numOctaves="3" seed="9" result="smoke-noise" />
      <feDisplacementMap in="SourceGraphic" in2="smoke-noise" scale="18" xChannelSelector="R" yChannelSelector="G" />
      <feGaussianBlur stdDeviation="0.6" />
    </filter>
  </defs>
</svg>
</div>

<style>
  .brand-space { min-width: 0; }
  .inline-space { width: 100%; container-type: inline-size; }
  .effect-definitions { position: absolute; width: 0; height: 0; pointer-events: none; }
  .branding {
    display: grid; grid-template-columns: 44px max-content; grid-template-rows: 44px 48px;
    align-items: center; column-gap: var(--space-xs); min-width: 0;
  }
  .logo-button {
    display: grid; place-items: center; width: 44px; height: 44px; padding: 0;
    border: 0; border-radius: var(--radius-input); background: transparent;
    color: var(--color-accent); cursor: pointer; touch-action: manipulation;
  }
  .label { min-width: 0; }
  .spell-slot { grid-column: 1 / -1; position: relative; align-self: stretch; pointer-events: none; }
  .spell {
    position: absolute; inset: var(--space-md) var(--space-xs) auto;
    width: max-content; white-space: nowrap;
    color: var(--color-accent-deep); font: 500 var(--text-sm)/1.25 var(--font-display);
    letter-spacing: 0;
  }
  .letter {
    display: inline-block; white-space: pre; transform-origin: 50% 80%;
    animation: inscribe 420ms var(--ease-out) calc(var(--index) * 26ms) both,
      dissolve 900ms ease-in calc(1900ms + var(--index) * 9ms) forwards;
  }
  .spell::before, .spell::after {
    content: attr(data-text); position: absolute; inset: 0; opacity: 0; pointer-events: none;
    color: var(--color-accent); transform-origin: 50% 80%;
    animation: smoke 1100ms ease-out 1900ms both;
  }
  .spell::after {
    color: var(--color-accent-2); animation-name: smoke-curl;
  }
  .inline { grid-template-columns: 44px max-content minmax(0, 1fr); grid-template-rows: 64px; }
  .inline .spell-slot { grid-column: 3; height: 64px; }
  .inline .spell { inset: 24px var(--space-2xs) auto; }
  @container (max-width: 270px) {
    .inline { grid-template-columns: 44px max-content; grid-template-rows: 44px 48px; }
    .inline .spell-slot { grid-column: 1 / -1; height: auto; }
    .inline .spell { inset: var(--space-md) var(--space-xs) auto; }
  }
  @keyframes inscribe {
    0% { opacity: 0; transform: translateY(8px) scale(0.7) rotate(-8deg); filter: blur(5px); text-shadow: 0 0 14px var(--color-accent-2); }
    65% { opacity: 1; transform: translateY(-2px) scale(1.06); filter: blur(0); text-shadow: 0 0 12px var(--color-accent-2); }
    100% { opacity: 1; transform: none; filter: blur(0); text-shadow: 0 0 6px var(--color-accent-2); }
  }
  @keyframes dissolve {
    0% { opacity: 1; transform: none; filter: blur(0); }
    35% { opacity: 0.5; transform: translate(calc(var(--drift) * 0.4), -4px) skewX(var(--turn)) scale(1.05, 1.2); filter: blur(1px); }
    100% { opacity: 0; transform: translate(var(--drift), -15px) rotate(var(--turn)) scale(1.3, 1.7); filter: blur(5px); }
  }
  @keyframes smoke {
    0% { opacity: 0; transform: none; filter: var(--smoke-filter) blur(1px); }
    20% { opacity: 0.32; }
    55% { opacity: 0.2; transform: translate(-3px, -8px) skewX(-8deg) scale(1.03, 1.4); filter: var(--smoke-filter) blur(3px); }
    100% { opacity: 0; transform: translate(5px, -17px) skewX(12deg) scale(1.1, 1.8); filter: var(--smoke-filter) blur(6px); }
  }
  @keyframes smoke-curl {
    0% { opacity: 0; transform: translateY(2px); filter: var(--smoke-filter) blur(2px); }
    25% { opacity: 0.26; }
    60% { opacity: 0.16; transform: translate(4px, -6px) skewX(10deg) scale(1.08, 1.3); filter: var(--smoke-filter) blur(4px); }
    100% { opacity: 0; transform: translate(-5px, -14px) skewX(-14deg) scale(1.12, 1.7); filter: var(--smoke-filter) blur(7px); }
  }
  @media (prefers-reduced-motion: reduce) {
    .letter { animation: none; opacity: 1; transform: none; filter: none; text-shadow: none; }
    .spell::before, .spell::after { display: none; animation: none; }
  }
</style>