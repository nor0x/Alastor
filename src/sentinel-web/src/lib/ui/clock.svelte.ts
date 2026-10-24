// A shared, coarse "now" so relative times ("3m ago") tick without each component running a timer.
export const clock = $state({ now: Date.now() });
setInterval(() => (clock.now = Date.now()), 15_000);
