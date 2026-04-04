const CACHE = 'agent-mesh-v2';
const ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './pkg/agent_mesh_wasm.js',
  './pkg/agent_mesh_wasm_bg.wasm',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  // Skip non-GET and API/relay requests (let them go straight to network).
  if (e.request.method !== 'GET') return;
  if (e.request.url.includes('/relay/') || e.request.url.includes('/agents') || e.request.url.includes('/oauth/')) {
    return;
  }

  // Stale-while-revalidate: serve from cache immediately, then update cache
  // in the background. This ensures WASM binary updates are picked up on
  // the next page load without requiring a manual cache version bump.
  e.respondWith(
    caches.open(CACHE).then((cache) =>
      cache.match(e.request).then((cached) => {
        const fetched = fetch(e.request).then((response) => {
          if (response.ok) {
            cache.put(e.request, response.clone());
          }
          return response;
        });
        return cached || fetched;
      })
    )
  );
});
