/**
 * Resolve the Control-Plane base URL and derived relay URL.
 * If the user left cp-url blank, use the current origin.
 */
function resolveCpUrl(raw: string): string {
  const trimmed = raw.trim();
  return (trimmed || window.location.origin).replace(/\/+$/, "");
}

function relayUrl(cp: string): string {
  return cp.replace(/^http/, "ws") + "/relay/ws";
}

export function useApi(cpUrlRaw: string) {
  const cp = resolveCpUrl(cpUrlRaw);
  const relay = relayUrl(cp);

  return { cp, relay } as const;
}
