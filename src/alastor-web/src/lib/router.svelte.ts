// Hand-rolled history router: a reactive path plus a click handler for in-app links.
// The server serves index.html for every non-API path, so deep links and reloads work.

export const route = $state({ path: location.pathname, search: location.search });

let leaveGuard: (() => boolean) | null = null;

/** A page with unsaved work registers a guard; returning false cancels in-app navigation. Returns the unregister function. */
export function setLeaveGuard(guard: () => boolean): () => void {
  leaveGuard = guard;
  return () => {
    if (leaveGuard === guard) leaveGuard = null;
  };
}

export function navigate(to: string, replace = false) {
  if (to === location.pathname + location.search) return;
  if (!replace && leaveGuard && to.split('?')[0] !== location.pathname && !leaveGuard()) return;
  if (replace) history.replaceState(null, '', to);
  else history.pushState(null, '', to);
  sync();
  if (!replace) window.scrollTo(0, 0);
}

function sync() {
  route.path = location.pathname;
  route.search = location.search;
}

window.addEventListener('popstate', sync);

// Plain <a href="/…"> links navigate in-app; modifier clicks, new tabs and external links behave normally.
document.addEventListener('click', (e) => {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  const a = (e.target as Element | null)?.closest?.('a');
  if (!a || a.target || a.hasAttribute('download') || a.origin !== location.origin) return;
  if (a.pathname.startsWith('/api/') || a.pathname.startsWith('/openapi') || a.pathname.startsWith('/install/')) return;
  e.preventDefault();
  navigate(a.pathname + a.search);
});

/** Matches "/hosts/:id" style patterns. Returns the params, or null. */
export function match(pattern: string, path: string): Record<string, string> | null {
  const p = pattern.split('/').filter(Boolean);
  const s = path.split('/').filter(Boolean);
  if (p.length !== s.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < p.length; i++) {
    if (p[i].startsWith(':')) params[p[i].slice(1)] = decodeURIComponent(s[i]);
    else if (p[i] !== s[i]) return null;
  }
  return params;
}
