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
  // Network-first for API, cache-first for assets
  if (e.request.url.includes('/relay/') || e.request.url.includes('/agents')) {
    return;
  }
  e.respondWith(
    caches.match(e.request).then((r) => r || fetch(e.request))
  );
});
