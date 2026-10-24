import { HubConnectionBuilder, HubConnectionState, LogLevel, type HubConnection } from '@microsoft/signalr';

// One SignalR connection to /hubs/dashboard for the whole app. Messages are invalidation hints: pages
// re-fetch over REST. When the hub is down, pages fall back to polling (see `usePolling`).

export const live = $state({ connected: false });

type Handler = (...args: unknown[]) => void;
const handlers = new Map<string, Set<Handler>>();
let hub: HubConnection | undefined;

export function startLive() {
  if (hub) return;
  hub = new HubConnectionBuilder().withUrl('/hubs/dashboard').withAutomaticReconnect([0, 2000, 5000, 10000, 30000]).configureLogging(LogLevel.Warning).build();
  for (const name of ['hostUpdated', 'eventsCreated', 'bansChanged', 'policyChanged', 'commandUpdated', 'feedUpdated', 'baselineUpdated'])
    hub.on(name, (...args: unknown[]) => handlers.get(name)?.forEach((h) => h(...args)));
  hub.onreconnecting(() => (live.connected = false));
  hub.onreconnected(() => (live.connected = true));
  hub.onclose(() => {
    live.connected = false;
    // Automatic reconnect gave up (server down for a while). Keep trying slowly.
    setTimeout(() => connect(), 30_000);
  });
  connect();
}

function connect() {
  if (!hub || hub.state !== HubConnectionState.Disconnected) return;
  hub.start().then(() => (live.connected = true)).catch(() => setTimeout(connect, 15_000));
}

export function stopLive() {
  const h = hub;
  hub = undefined;
  live.connected = false;
  h?.stop();
}

/** Subscribe to a hub message; returns the unsubscribe function (use as an $effect cleanup). */
export function on<T extends unknown[]>(name: string, handler: (...args: T) => void): () => void {
  let set = handlers.get(name);
  if (!set) handlers.set(name, (set = new Set()));
  set.add(handler as unknown as Handler);
  return () => set.delete(handler as unknown as Handler);
}

/**
 * Calls `refresh` on every named hub message (debounced), and every `fallbackMs` while the hub is disconnected.
 * Call inside an $effect or onMount and return the result as cleanup.
 */
export function refreshOn(names: string[], refresh: () => void, fallbackMs = 15_000): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const debounced = () => {
    clearTimeout(timer);
    timer = setTimeout(refresh, 400);
  };
  const offs = names.map((n) => on(n, debounced));
  const poll = setInterval(() => {
    if (!live.connected) refresh();
  }, fallbackMs);
  return () => {
    clearTimeout(timer);
    clearInterval(poll);
    offs.forEach((off) => off());
  };
}
