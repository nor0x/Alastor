<script lang="ts">
  import { shortTime, fullDate } from '../format';

  // One series per chart (small multiples): CPU, memory, disk and load each get their own y-scale,
  // so there is never a second axis. A single series needs no legend; the title names it.
  let { title, detail, points, unit = '%', max }: {
    title: string;
    /** A quieter second line under the title, e.g. "2.9 GB of 4.0 GB". */
    detail?: string;
    points: { at: string; value: number }[];
    unit?: string;
    /** Fixed y maximum (100 for percentages); otherwise derived from the data. */
    max?: number;
  } = $props();

  const H = 120;
  const PAD = { top: 8, right: 8, bottom: 20, left: 34 };
  let width = $state(320);
  let hover = $state<number | null>(null);

  const t0 = $derived(points.length ? new Date(points[0].at).getTime() : 0);
  const t1 = $derived(points.length ? new Date(points[points.length - 1].at).getTime() : 1);
  const yMax = $derived(max ?? niceMax(Math.max(0.1, ...points.map((p) => p.value))));
  const plotW = $derived(Math.max(10, width - PAD.left - PAD.right));
  const plotH = H - PAD.top - PAD.bottom;

  const x = (t: number) => PAD.left + (t1 === t0 ? plotW : ((t - t0) / (t1 - t0)) * plotW);
  const y = (v: number) => PAD.top + plotH - (Math.min(v, yMax) / yMax) * plotH;

  const coords = $derived(points.map((p) => [x(new Date(p.at).getTime()), y(p.value)] as const));

  // Break the line where samples are missing (agent offline) instead of drawing a straight bridge across the gap.
  const gapMs = $derived.by(() => {
    const deltas = points.slice(1).map((p, i) => new Date(p.at).getTime() - new Date(points[i].at).getTime()).sort((a, b) => a - b);
    const median = deltas.length ? deltas[Math.floor(deltas.length / 2)] : 60_000;
    return Math.max(5 * 60_000, median * 5);
  });
  const segments = $derived.by(() => {
    const out: (readonly [number, number])[][] = [];
    points.forEach((p, i) => {
      const t = new Date(p.at).getTime();
      if (i === 0 || t - new Date(points[i - 1].at).getTime() > gapMs) out.push([]);
      out[out.length - 1].push(coords[i]);
    });
    return out;
  });
  const path = (seg: (readonly [number, number])[]) => seg.map(([cx, cy], i) => `${i ? 'L' : 'M'}${cx.toFixed(1)},${cy.toFixed(1)}`).join('');
  const line = $derived(segments.map(path).join(''));
  const area = $derived(
    segments.filter((seg) => seg.length > 1).map((seg) => `${path(seg)}L${seg[seg.length - 1][0].toFixed(1)},${PAD.top + plotH}L${seg[0][0].toFixed(1)},${PAD.top + plotH}Z`).join(''),
  );
  const ticks = $derived([0, yMax / 2, yMax]);
  // Time ticks at the start, middle and end of the range (by time, not by sample), dropping the middle one when it would collide.
  const xTicks = $derived.by(() => {
    if (points.length < 2) return [];
    const all = [t0, (t0 + t1) / 2, t1];
    return plotW < 200 ? [t0, t1] : all;
  });
  const latest = $derived(points.length ? points[points.length - 1].value : null);

  function niceMax(v: number) {
    const mag = 10 ** Math.floor(Math.log10(v));
    for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * mag) return m * mag;
    return 10 * mag;
  }

  function fmt(v: number) {
    return unit === '%' ? `${v.toFixed(v < 10 ? 1 : 0)}%` : v.toFixed(2);
  }

  function onMove(e: PointerEvent) {
    const rect = (e.currentTarget as SVGElement).getBoundingClientRect();
    const px = e.clientX - rect.left;
    let best = 0;
    for (let i = 1; i < coords.length; i++) if (Math.abs(coords[i][0] - px) < Math.abs(coords[best][0] - px)) best = i;
    hover = coords.length ? best : null;
  }
</script>

<figure class="chart">
  <figcaption>
    <span class="title">{title}{#if detail}<span class="detail">{detail}</span>{/if}</span>
    {#if latest !== null}<span class="value">{fmt(latest)}</span>{/if}
  </figcaption>
  <div class="plot" bind:clientWidth={width}>
    {#if points.length < 2}
      <div class="nodata" style:height="{H}px">Not enough samples yet</div>
    {:else}
      <svg {width} height={H} role="img" aria-label="{title} over time, latest {latest !== null ? fmt(latest) : 'n/a'}"
        onpointermove={onMove} onpointerleave={() => (hover = null)}>
        {#each ticks as t (t)}
          <line class="grid" x1={PAD.left} x2={PAD.left + plotW} y1={y(t)} y2={y(t)} />
          <text class="axis" x={PAD.left - 6} y={y(t)} dy="0.32em" text-anchor="end">{unit === '%' ? `${t}` : t.toFixed(t < 1 ? 2 : 1)}</text>
        {/each}
        {#each xTicks as t, i (t)}
          <text class="axis" x={x(t)} y={H - 4} text-anchor={i === 0 ? 'start' : i === xTicks.length - 1 ? 'end' : 'middle'}>{shortTime(new Date(t).toISOString())}</text>
        {/each}
        <path class="area" d={area} />
        <path class="line" d={line} />
        {#if hover !== null}
          <line class="cross" x1={coords[hover][0]} x2={coords[hover][0]} y1={PAD.top} y2={PAD.top + plotH} />
          <circle class="marker" cx={coords[hover][0]} cy={coords[hover][1]} r="4" />
        {/if}
      </svg>
      {#if hover !== null}
        <div class="tip" style:left="{Math.min(Math.max(coords[hover][0], 60), width - 60)}px">
          <strong>{fmt(points[hover].value)}</strong>
          <span>{fullDate(points[hover].at)}</span>
        </div>
      {/if}
    {/if}
  </div>
</figure>

<style>
  .chart { margin: 0; min-width: 0; }
  figcaption { display: flex; justify-content: space-between; align-items: flex-start; gap: var(--space-xs); margin-bottom: var(--space-xs); }
  .title { display: flex; flex-direction: column; gap: var(--space-3xs); font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--muted); }
  .detail { font-family: var(--font-body); font-weight: 400; font-size: var(--text-xs); }
  .value { font-family: var(--font-display); color: var(--text-strong); font-size: var(--text-figure-s); font-weight: 600; line-height: 1; letter-spacing: var(--tracking-display); font-variant-numeric: tabular-nums; }
  .plot { position: relative; }
  svg { display: block; touch-action: none; }
  .grid { stroke: var(--border); stroke-width: 1; }
  .axis { fill: var(--muted); font-family: var(--font-body); font-size: 10px; font-variant-numeric: tabular-nums; }
  .line { fill: none; stroke: var(--color-accent); stroke-width: 1.5; stroke-linejoin: round; stroke-linecap: round; }
  .area { fill: var(--color-accent-wash); }
  .cross { stroke: var(--color-ink-2); stroke-width: 1; stroke-dasharray: 2 3; }
  .marker { fill: var(--color-accent); stroke: var(--color-key-face); stroke-width: 2; }
  .tip {
    position: absolute; top: calc(-1 * var(--space-xs)); transform: translate(-50%, -100%); pointer-events: none; z-index: var(--z-tooltip);
    display: flex; flex-direction: column; align-items: center; padding: var(--space-2xs) var(--space-xs); border-radius: 4px;
    background: var(--color-graphite); font-size: var(--text-xs); white-space: nowrap; color: var(--color-graphite-muted);
  }
  .tip strong { color: var(--color-graphite-ink); font-family: var(--font-display); font-weight: 600; font-size: var(--text-md); }
  .nodata { display: grid; place-items: center; color: var(--muted); font-size: var(--text-sm); border: var(--rule-hair) dashed var(--border-strong); border-radius: var(--radius-input); }
</style>
