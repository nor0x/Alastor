<script lang="ts">
  import { compact, niceMax, type Bucket, type Series } from './chart';
  import { number } from '../format';

  // Columns of stacked counts over time (events per day by severity, bans per hour). The first series sits on the
  // baseline. Each column is its own hover target; arrow keys move between columns when the chart has focus.
  // A legend with range totals is always shown for two or more series, and the same numbers are in the table view.

  let { title, series, buckets, height = 150, empty = 'Nothing in this period.' }: {
    title: string;
    series: Series[];
    buckets: Bucket[];
    height?: number;
    empty?: string;
  } = $props();

  const PAD = { top: 8, right: 4, bottom: 20, left: 34 };
  const GAP = 2;
  let width = $state(320);
  let hover = $state<number | null>(null);

  const total = (b: Bucket) => series.reduce((s, x) => s + (b.values[x.key] ?? 0), 0);
  const yMax = $derived(niceMax(Math.max(1, ...buckets.map(total))));
  const plotW = $derived(Math.max(10, width - PAD.left - PAD.right));
  const plotH = $derived(height - PAD.top - PAD.bottom);
  const band = $derived(plotW / Math.max(1, buckets.length));
  const barW = $derived(Math.max(2, Math.min(24, band - 4)));
  const y = (v: number) => PAD.top + plotH - (v / yMax) * plotH;
  const ticks = $derived(Number.isInteger(yMax / 2) ? [0, yMax / 2, yMax] : [0, yMax]);
  // About one x label per 60px, always including the last bucket.
  const labelEvery = $derived(Math.max(1, Math.ceil(buckets.length / Math.max(2, Math.floor(plotW / 60)))));
  const sums = $derived(series.map((s) => buckets.reduce((acc, b) => acc + (b.values[s.key] ?? 0), 0)));
  const grand = $derived(sums.reduce((a, b) => a + b, 0));

  // Segments bottom-up, with a surface gap between them; only the top segment gets the rounded data end.
  const columns = $derived(
    buckets.map((b, i) => {
      const x = PAD.left + i * band + (band - barW) / 2;
      let acc = 0;
      const segs: { key: string; color: string; y: number; h: number }[] = [];
      for (const s of series) {
        const v = b.values[s.key] ?? 0;
        if (v <= 0) continue;
        const top = y(acc + v);
        const bottom = y(acc);
        acc += v;
        segs.push({ key: s.key, color: s.color, y: top, h: Math.max(1, bottom - top - (segs.length ? GAP : 0)) });
      }
      return { x, segs };
    }),
  );

  function roundedTop(x: number, y: number, w: number, h: number, r = 4) {
    const rr = Math.min(r, w / 2, h);
    return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`;
  }

  function onKey(e: KeyboardEvent) {
    if (!buckets.length) return;
    if (e.key === 'ArrowRight') hover = Math.min(buckets.length - 1, (hover ?? -1) + 1);
    else if (e.key === 'ArrowLeft') hover = Math.max(0, (hover ?? buckets.length) - 1);
    else if (e.key === 'Escape') hover = null;
    else return;
    e.preventDefault();
  }
</script>

<figure class="chart">
  <figcaption>
    <span class="title">{title}</span>
    {#if series.length > 1}
      <span class="legend">
        {#each series as s, i (s.key)}
          <span class="item"><span class="swatch" style:background={s.color}></span>{s.label} <span class="n">{number.format(sums[i])}</span></span>
        {/each}
      </span>
    {:else}
      <span class="value">{number.format(grand)}</span>
    {/if}
  </figcaption>
  <div class="plot" bind:clientWidth={width}>
    {#if grand === 0}
      <div class="nodata" style:height="{height}px">{empty}</div>
    {:else}
      <!-- Focusable so keyboard users can step through columns with the arrow keys. -->
      <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
      <svg {width} {height} role="img" tabindex="0" aria-label="{title}: {number.format(grand)} in total. Use the arrow keys to read each column."
        onkeydown={onKey} onpointerleave={() => (hover = null)} onblur={() => (hover = null)}>
        {#each ticks as t (t)}
          <line class="grid" x1={PAD.left} x2={PAD.left + plotW} y1={y(t)} y2={y(t)} />
          <text class="axis" x={PAD.left - 6} y={y(t)} dy="0.32em" text-anchor="end">{compact.format(t)}</text>
        {/each}
        {#each columns as c, i (buckets[i].key)}
          <g class="col" class:dim={hover !== null && hover !== i}>
            {#each c.segs as s, j (s.key)}
              {#if j === c.segs.length - 1}<path d={roundedTop(c.x, s.y, barW, s.h)} fill={s.color} />
              {:else}<rect x={c.x} y={s.y} width={barW} height={s.h} fill={s.color} />{/if}
            {/each}
          </g>
          {#if i % labelEvery === (buckets.length - 1) % labelEvery}
            <!-- Edge labels anchor inward so they never run past the plot. -->
            <text class="axis" x={PAD.left + i * band + band / 2} y={height - 4}
              text-anchor={i * band < 30 ? 'start' : (buckets.length - 1 - i) * band < 30 ? 'end' : 'middle'}
              dx={i * band < 30 ? -barW / 2 : (buckets.length - 1 - i) * band < 30 ? barW / 2 : 0}>{buckets[i].label}</text>
          {/if}
          <!-- The whole column band is the hit target, not just the painted bar. -->
          <rect class="hit" x={PAD.left + i * band} y={PAD.top} width={band} height={plotH} role="presentation" onpointerenter={() => (hover = i)} />
        {/each}
      </svg>
      {#if hover !== null}
        {@const b = buckets[hover]}
        <div class="tip" style:left="{Math.min(Math.max(PAD.left + hover * band + band / 2, 80), width - 80)}px">
          <span class="when">{b.label}</span>
          {#each [...series].reverse() as s (s.key)}
            {#if (b.values[s.key] ?? 0) > 0 || series.length <= 2}
              <span class="row"><span class="key" style:background={s.color}></span><strong>{number.format(b.values[s.key] ?? 0)}</strong> {s.label}</span>
            {/if}
          {/each}
          {#if series.length > 1}<span class="row tot"><strong>{number.format(total(b))}</strong> total</span>{/if}
        </div>
      {/if}
    {/if}
  </div>
  {#if grand > 0}
    <details class="tableview">
      <summary>Table</summary>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th></th>{#each series as s (s.key)}<th class="num">{s.label}</th>{/each}{#if series.length > 1}<th class="num">Total</th>{/if}</tr></thead>
          <tbody>
            {#each buckets as b (b.key)}
              <tr><td class="nowrap">{b.label}</td>{#each series as s (s.key)}<td class="num">{number.format(b.values[s.key] ?? 0)}</td>{/each}{#if series.length > 1}<td class="num">{number.format(total(b))}</td>{/if}</tr>
            {/each}
          </tbody>
        </table>
      </div>
    </details>
  {/if}
</figure>

<style>
  .chart { margin: 0; min-width: 0; }
  figcaption { display: flex; justify-content: space-between; align-items: flex-start; gap: var(--space-xs) var(--space-md); flex-wrap: wrap; margin-bottom: var(--space-xs); }
  .title { font-family: var(--font-display); font-weight: 500; font-size: var(--text-sm); color: var(--muted); }
  .value { font-family: var(--font-display); color: var(--text-strong); font-size: var(--text-figure-s); font-weight: 600; line-height: 1; letter-spacing: var(--tracking-display); font-variant-numeric: tabular-nums; }
  .legend { display: flex; flex-wrap: wrap; gap: var(--space-2xs) var(--space-sm); font-size: var(--text-xs); color: var(--muted); }
  .item { display: inline-flex; align-items: center; gap: var(--space-2xs); }
  .swatch { width: 10px; height: 10px; border-radius: 2px; }
  .n { color: var(--text-strong); font-weight: 500; font-variant-numeric: tabular-nums; }
  .plot { position: relative; }
  svg { display: block; touch-action: pan-y; }
  svg:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; border-radius: 4px; }
  .grid { stroke: var(--border); stroke-width: 1; }
  .axis { fill: var(--muted); font-family: var(--font-body); font-size: 10px; font-variant-numeric: tabular-nums; }
  .col { transition: opacity var(--dur-micro) var(--ease-out); }
  .col.dim { opacity: 0.4; }
  .hit { fill: transparent; }
  .tip {
    position: absolute; top: calc(-1 * var(--space-xs)); transform: translate(-50%, -100%); pointer-events: none; z-index: var(--z-tooltip);
    display: flex; flex-direction: column; gap: var(--space-3xs); padding: var(--space-xs) var(--space-sm); border-radius: 4px;
    background: var(--color-graphite); font-size: var(--text-xs); white-space: nowrap; color: var(--color-graphite-muted);
  }
  .when { margin-bottom: var(--space-3xs); font-family: var(--font-display); font-weight: 500; }
  .row { display: flex; align-items: center; gap: var(--space-xs); }
  .row strong { color: var(--color-graphite-ink); font-family: var(--font-display); font-weight: 600; font-variant-numeric: tabular-nums; }
  /* A ring of graphite-ink keeps the darkest fills visible on the graphite tooltip. */
  .key { width: 8px; height: 8px; border-radius: 2px; box-shadow: 0 0 0 1px color-mix(in oklab, var(--color-graphite-ink) 35%, transparent); }
  .tot { margin-top: var(--space-3xs); padding-top: var(--space-2xs); border-top: var(--rule-hair) solid var(--color-graphite-2); }
  .nodata { display: grid; place-items: center; padding: 0 var(--space-md); text-align: center; color: var(--muted); font-size: var(--text-sm); border: var(--rule-hair) dashed var(--border-strong); border-radius: var(--radius-input); }
  .tableview { margin-top: var(--space-xs); font-size: var(--text-sm); }
  .tableview summary { width: fit-content; color: var(--muted); font-family: var(--font-display); font-weight: 500; cursor: pointer; }
  .tableview summary:hover { color: var(--text-strong); }
  .tableview .table-wrap { max-height: 240px; overflow: auto; margin-top: var(--space-xs); border: var(--rule-hair) solid var(--border); border-radius: var(--radius-input); }
  .tableview .table td { height: 32px; }
</style>
