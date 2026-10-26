<script lang="ts">
  // The Alastor mark: a ring on a broken diagonal, with a pupil that watches the cursor.
  let { size = 16 }: { size?: number } = $props();

  // How far the pupil may travel, in viewBox units: ring inner radius (3.85) minus pupil radius (1.8), less a hair.
  const REACH = 1.6;
  // Cursor distance in px at which the pupil reaches the edge of the ring.
  const FULL = 120;

  let svg: SVGSVGElement;
  let dx = $state(0);
  let dy = $state(0);
  let frame = 0;

  function look(e: PointerEvent) {
    const { clientX, clientY } = e;
    if (frame) cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => {
      frame = 0;
      const r = svg.getBoundingClientRect();
      const x = clientX - (r.left + r.width / 2);
      const y = clientY - (r.top + r.height / 2);
      const d = Math.hypot(x, y);
      const k = d ? (REACH * Math.min(1, d / FULL)) / d : 0;
      dx = x * k;
      dy = y * k;
    });
  }

  function leave(e: MouseEvent) {
    if (e.relatedTarget) return;
    if (frame) cancelAnimationFrame(frame);
    frame = 0;
    dx = dy = 0;
  }

  $effect(() => () => { if (frame) cancelAnimationFrame(frame); });
</script>

<svelte:window onpointermove={look} onmouseout={leave} />

<svg bind:this={svg} class="logo" viewBox="0 0 16 16" width={size} height={size} fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="square" aria-hidden="true">
  <path d="M2.25 2.25 4.75 4.75M11.25 11.25 13.75 13.75" />
  <circle cx="8" cy="8" r="4.6" />
  <circle class="pupil" cx="8" cy="8" r="1.8" fill="currentColor" stroke="none" style:transform="translate({dx}px, {dy}px)" />
</svg>

<style>
  .logo { flex: none; display: inline-block; vertical-align: -0.15em; }
  .pupil { transition: transform 120ms ease-out; }
  @media (prefers-reduced-motion: reduce) { .pupil { transform: none !important; } }
</style>
