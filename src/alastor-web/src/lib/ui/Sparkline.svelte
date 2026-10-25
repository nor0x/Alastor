<script lang="ts">
  // A tiny trend line for stat tiles: no axes, the tile's number is the value. Null days leave a gap.
  let { values, label, height = 28 }: { values: (number | null)[]; label: string; height?: number } = $props();

  let width = $state(120);
  const known = $derived(values.filter((v): v is number => v !== null));
  const lo = $derived(Math.min(...known));
  const hi = $derived(Math.max(...known));
  const x = (i: number) => (values.length < 2 ? width : (i / (values.length - 1)) * (width - 4) + 2);
  const y = (v: number) => (hi === lo ? height / 2 : height - 3 - ((v - lo) / (hi - lo)) * (height - 6));
  const path = $derived(
    values.map((v, i) => (v === null ? '' : `${i === 0 || values[i - 1] === null ? 'M' : 'L'}${x(i).toFixed(1)},${y(v).toFixed(1)}`)).join(''),
  );
  const last = $derived.by(() => {
    for (let i = values.length - 1; i >= 0; i--) if (values[i] !== null) return i;
    return -1;
  });
</script>

<div class="spark" bind:clientWidth={width}>
  {#if known.length >= 2}
    <svg {width} {height} role="img" aria-label="{label}: from {known[0]} to {known[known.length - 1]}">
      <path d={path} />
      <circle cx={x(last)} cy={y(values[last] as number)} r="2.5" />
    </svg>
  {/if}
</div>

<style>
  .spark { width: 100%; min-height: 4px; }
  svg { display: block; overflow: visible; }
  path { fill: none; stroke: var(--muted); stroke-width: 1.5; stroke-linejoin: round; stroke-linecap: round; }
  circle { fill: var(--info); stroke: var(--surface); stroke-width: 2; }
</style>
